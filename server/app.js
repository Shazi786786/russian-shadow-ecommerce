import express from 'express';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import QRCode from 'qrcode';
import crypto from 'node:crypto';
import pg from 'pg';

const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:{rejectUnauthorized:false},max:4,connectionTimeoutMillis:10000});
const secret=process.env.JWT_SECRET;
const app=express();app.use(express.json({limit:'3mb'}));app.use(cookieParser());
const query=async(sql,...params)=>(await pool.query(sql,params)).rows;
const one=async(sql,...params)=>(await query(sql,...params))[0];
const fail=(r,c,m)=>r.status(c).json({error:m});
const wrap=fn=>(req,res,next)=>Promise.resolve(fn(req,res,next)).catch(e=>{console.error('API error',e.code||e.message);if(e.code==='23505'||e.code==='23503'||e.code==='23514')return fail(res,400,'Duplicate or invalid value');return fail(res,500,'Request failed');});
const guard=wrap(async(req,res,next)=>{if(!secret||secret.length<32)return fail(res,503,'Authentication not configured');let payload;try{payload=jwt.verify(req.cookies.rs_token,secret)}catch{return fail(res,401,'Please sign in')};const u=await one('SELECT id,username,role,balance_cents FROM users WHERE id=$1',payload.id);if(!u)return fail(res,401,'Please sign in');req.user=u;next()});
const roles=(...allowed)=>(req,res,next)=>allowed.includes(req.user.role)?next():fail(res,403,'Not permitted');
const cost=p=>({...p,price:Number(p.price_cents)/100});
const numeric=v=>Number.isSafeInteger(Number(v))&&Number(v)>0&&Number(v)<=100000000?Number(v):null;
const activityIp=req=>String(req.headers['x-real-ip']||String(req.headers['x-forwarded-for']||'').split(',')[0]||req.ip||'').slice(0,64);
const recordActivity=async(req,userId,type)=>{await query('INSERT INTO user_activity(user_id,event_type,ip_address) VALUES($1,$2,$3)',userId,type,activityIp(req));};
const authCookie=(res,id)=>res.cookie('rs_token',jwt.sign({id},secret,{expiresIn:'7d'}),{httpOnly:true,secure:process.env.NODE_ENV==='production',sameSite:'lax',maxAge:604800000});
app.get('/api/health',wrap(async(_req,res)=>{await query('SELECT 1');res.json({ok:true,database:'connected'})}));
app.post('/api/auth/register',wrap(async(req,res)=>{const {username,password}=req.body||{};if(!/^[a-zA-Z0-9_]{3,30}$/.test(username||'')||typeof password!=='string'||password.length<10||password.length>128)return fail(res,400,'Use 3–30 character username and 10+ character password');if(!secret||secret.length<32)return fail(res,503,'Authentication not configured');const hash=await bcrypt.hash(password,12);const u=await one("INSERT INTO users(username,password_hash,role) VALUES($1,$2,'user') RETURNING id",username,hash);authCookie(res,u.id);await recordActivity(req,u.id,'register');res.json({ok:true})}));
app.post('/api/auth/login',wrap(async(req,res)=>{const u=await one('SELECT * FROM users WHERE username=$1',req.body?.username||'');if(!u||!await bcrypt.compare(String(req.body?.password||''),u.password_hash))return fail(res,401,'Invalid credentials');authCookie(res,u.id);await recordActivity(req,u.id,'login');res.json({ok:true})}));
app.post('/api/auth/logout',wrap(async(req,res)=>{try{const token=jwt.verify(req.cookies.rs_token,secret);await recordActivity(req,token.id,'logout')}catch{}res.clearCookie('rs_token');res.json({ok:true})}));
app.get('/api/me',guard,(req,res)=>res.json(req.user));
app.post('/api/activity/visit',guard,wrap(async(req,res)=>{const recent=await one("SELECT id FROM user_activity WHERE user_id=$1 AND event_type='visit' AND created_at>now()-interval '10 minutes' ORDER BY id DESC LIMIT 1",req.user.id);if(!recent)await recordActivity(req,req.user.id,'visit');res.json({ok:true})}));
app.get('/api/admin/activity',guard,roles('admin'),wrap(async(_req,res)=>{await query("DELETE FROM user_activity WHERE created_at<now()-interval '30 days'");const users=await query("SELECT u.id,u.username,u.role,u.balance_cents,u.created_at,MAX(a.created_at) FILTER (WHERE a.event_type IN ('login','visit','register')) AS last_seen_at,MAX(a.created_at) FILTER (WHERE a.event_type='login') AS last_login_at,MAX(a.created_at) FILTER (WHERE a.event_type='logout') AS last_logout_at FROM users u LEFT JOIN user_activity a ON a.user_id=u.id GROUP BY u.id ORDER BY u.id DESC");const events=await query("SELECT a.id,a.event_type,a.ip_address,a.created_at,u.username,u.id AS user_id FROM user_activity a JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 200");res.json({total_users:users.length,users,events})}));

app.get('/api/categories',wrap(async(_req,res)=>res.json(await query('SELECT * FROM categories ORDER BY id'))));
app.get('/api/products',wrap(async(req,res)=>{const {category,q}=req.query;const rows=await query(`SELECT p.*,c.name category,u.username seller FROM products p LEFT JOIN categories c ON c.id=p.category_id LEFT JOIN users u ON u.id=p.seller_id WHERE p.active=true AND ($1::text IS NULL OR c.slug=$1) AND ($2::text IS NULL OR p.title ILIKE '%'||$2||'%' OR p.description ILIKE '%'||$2||'%') ORDER BY p.id DESC`,category&&category!=='all'?category:null,q||null);res.json(rows.map(cost))}));
app.get('/api/products/:id',wrap(async(req,res)=>{const p=await one('SELECT * FROM products WHERE id=$1 AND active=true',req.params.id);return p?res.json(cost(p)):fail(res,404,'Product not found')}));
app.get('/api/public/sellers/:id',wrap(async(req,res)=>{
 const id=Number(req.params.id);
 if(!Number.isSafeInteger(id)||id<1)return fail(res,404,'Seller not found');
 const seller=await one("SELECT u.id,u.username,COALESCE((SELECT a.full_name FROM seller_applications a WHERE a.user_id=u.id AND a.status='approved' ORDER BY a.id DESC LIMIT 1),u.username) AS display_name,(SELECT a.service_category FROM seller_applications a WHERE a.user_id=u.id AND a.status='approved' ORDER BY a.id DESC LIMIT 1) AS service_category,(SELECT COUNT(*)::int FROM products p WHERE p.seller_id=u.id AND p.active=true) AS product_count FROM users u WHERE u.id=$1 AND u.role IN ('seller','admin')",id);
 if(!seller)return fail(res,404,'Seller not found');
 res.json(seller);
}));
app.get('/api/payments',guard,wrap(async(_req,res)=>res.json(await query("SELECT id,code,name,network FROM payment_methods WHERE enabled=true AND address<>''"))));
app.post('/api/deposits',guard,wrap(async(req,res)=>{const amount=numeric(req.body?.amount_cents);if(!amount)return fail(res,400,'Invalid amount');const m=await one("SELECT * FROM payment_methods WHERE id=$1 AND enabled=true AND address<>''",req.body?.method_id);if(!m)return fail(res,400,'Payment method unavailable');const d=await one("INSERT INTO deposits(user_id,method_id,amount_cents,address_snapshot,expires_at) VALUES($1,$2,$3,$4,now()+interval '30 minutes') RETURNING *",req.user.id,m.id,amount,m.address);res.json({id:d.id,amount_cents:amount,address:m.address,code:m.code,network:m.network,expires_at:d.expires_at})}));
app.get('/api/deposits',guard,wrap(async(req,res)=>res.json(await query('SELECT d.*,m.code,m.network FROM deposits d JOIN payment_methods m ON m.id=d.method_id WHERE d.user_id=$1 ORDER BY d.id DESC',req.user.id))));
app.patch('/api/deposits/:id/submit',guard,wrap(async(req,res)=>{const d=await one("UPDATE deposits SET status='pending',txid=$1 WHERE id=$2 AND user_id=$3 AND status='awaiting_payment' AND expires_at>now() RETURNING id",String(req.body?.txid||'').slice(0,200),req.params.id,req.user.id);return d?res.json({ok:true}):fail(res,400,'Deposit already submitted or payment window expired')}));
app.get('/api/wallet',guard,wrap(async(req,res)=>res.json({balance_cents:req.user.balance_cents,ledger:await query('SELECT * FROM ledger WHERE user_id=$1 ORDER BY id DESC',req.user.id)})));
app.post('/api/orders',guard,wrap(async(req,res)=>{const items=req.body?.items;if(!Array.isArray(items)||items.length<1||items.length>40)return fail(res,400,'Invalid cart');const quantities=new Map();for(const it of items){const id=Number(it.id),qty=Number(it.quantity);if(!Number.isSafeInteger(id)||!Number.isSafeInteger(qty)||qty<1||qty>100)return fail(res,400,'Invalid cart');quantities.set(id,(quantities.get(id)||0)+qty)}const client=await pool.connect();try{await client.query('BEGIN');const ordered=[];let total=0;for(const [id,qty] of [...quantities].sort((a,b)=>a[0]-b[0])){const p=(await client.query('SELECT * FROM products WHERE id=$1 AND active=true FOR UPDATE',[id])).rows[0];if(!p||p.stock<qty)throw Error('One or more products are out of stock');total+=Number(p.price_cents)*qty;ordered.push({p,qty})}if(total<=0)throw Error('Invalid order');const debit=await client.query('UPDATE users SET balance_cents=balance_cents-$1 WHERE id=$2 AND balance_cents >= $1 RETURNING id',[total,req.user.id]);if(!debit.rowCount)throw Error('Insufficient wallet balance');const order=(await client.query('INSERT INTO orders(user_id,total_cents) VALUES($1,$2) RETURNING id',[req.user.id,total])).rows[0];for(const {p,qty} of ordered){await client.query('UPDATE products SET stock=stock-$1 WHERE id=$2',[qty,p.id]);const oi=(await client.query('INSERT INTO order_items(order_id,product_id,seller_id,title,price_cents,quantity,delivery_text) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id',[order.id,p.id,p.seller_id,p.title,p.price_cents,qty,p.delivery_text])).rows[0];if(p.seller_id){const gross=Number(p.price_cents)*qty,commission=Math.round(gross*35/100);await client.query('INSERT INTO seller_earnings(order_item_id,seller_id,gross_cents,commission_cents,net_cents) VALUES($1,$2,$3,$4,$5)',[oi.id,p.seller_id,gross,commission,gross-commission])}}await client.query("INSERT INTO ledger(user_id,delta_cents,kind,reference_id) VALUES($1,$2,'purchase',$3)",[req.user.id,-total,order.id]);await client.query('COMMIT');res.json({ok:true,order_id:order.id})}catch(e){await client.query('ROLLBACK');return fail(res,400,e.message)}finally{client.release()}}));
app.get('/api/orders',guard,wrap(async(req,res)=>{const orders=await query('SELECT * FROM orders WHERE user_id=$1 ORDER BY id DESC',req.user.id);for(const o of orders)o.items=await query('SELECT * FROM order_items WHERE order_id=$1',o.id);res.json(orders)}));

/* Buyer confirmation and 72-hour refund request window; all transitions are atomic. */
app.patch('/api/orders/:id/confirm',guard,wrap(async(req,res)=>{
 const client=await pool.connect();
 try{await client.query('BEGIN');
 const o=(await client.query("UPDATE orders SET buyer_status='confirmed' WHERE id=$1 AND user_id=$2 AND buyer_status IN ('pending','refund_rejected') RETURNING id",[req.params.id,req.user.id])).rows[0];
 if(!o){await client.query('ROLLBACK');return fail(res,409,'This order cannot be confirmed')}
 await client.query('UPDATE seller_earnings SET released_at=now() WHERE order_item_id IN (SELECT id FROM order_items WHERE order_id=$1) AND released_at IS NULL AND voided_at IS NULL',[o.id]);
 await client.query('COMMIT');res.json({ok:true,status:'confirmed'});
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}));
app.post('/api/orders/:id/refund',guard,wrap(async(req,res)=>{
 const reason=String(req.body?.reason||'').trim();
 if(reason.length<10||reason.length>1500)return fail(res,400,'Please explain the issue (10–1500 characters)');
 const client=await pool.connect();
 try{await client.query('BEGIN');
 const o=(await client.query("SELECT * FROM orders WHERE id=$1 AND user_id=$2 AND buyer_status='pending' AND created_at>=now()-interval '3 days' FOR UPDATE",[req.params.id,req.user.id])).rows[0];
 if(!o){await client.query('ROLLBACK');return fail(res,409,'Refund available only within 3 days before confirming receipt')}
 const released=(await client.query("SELECT COUNT(*)::int AS n FROM seller_earnings se JOIN order_items oi ON oi.id=se.order_item_id WHERE oi.order_id=$1 AND se.released_at IS NOT NULL",[o.id])).rows[0];
 if(released.n){await client.query('ROLLBACK');return fail(res,409,'Seller payout already released; contact support')}
 await client.query('UPDATE users SET balance_cents=balance_cents+$1 WHERE id=$2',[o.total_cents,o.user_id]);
 await client.query("INSERT INTO ledger(user_id,delta_cents,kind,reference_id) VALUES($1,$2,'refund',$3)",[o.user_id,o.total_cents,o.id]);
 await client.query('UPDATE seller_earnings SET voided_at=now() WHERE order_item_id IN (SELECT id FROM order_items WHERE order_id=$1) AND voided_at IS NULL',[o.id]);
 await client.query("UPDATE orders SET buyer_status='refunded',refund_reason=$1,refund_requested_at=now() WHERE id=$2",[reason,o.id]);
 await client.query('COMMIT');res.json({ok:true,status:'refunded',credited_cents:o.total_cents});
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}));
app.get('/api/admin/refunds',guard,roles('admin'),wrap(async(_req,res)=>res.json(await query("SELECT o.id,o.user_id,u.username,o.total_cents,o.buyer_status,o.refund_reason,o.refund_requested_at,o.refund_admin_message,o.created_at FROM orders o JOIN users u ON u.id=o.user_id WHERE o.buyer_status IN ('refund_requested','refunded','refund_rejected') ORDER BY CASE WHEN o.buyer_status='refunded' AND o.refund_reviewed_at IS NULL THEN 0 ELSE 1 END,o.id DESC"))));
app.patch('/api/admin/refunds/:id',guard,roles('admin'),wrap(async(req,res)=>{
 const decision=req.body?.decision;
 const message=String(req.body?.message||'').trim();
 if(!['approve','reject'].includes(decision)||message.length>1500)return fail(res,400,'Invalid refund decision');
 const client=await pool.connect();
 try{await client.query('BEGIN');
 const o=(await client.query("SELECT * FROM orders WHERE id=$1 AND buyer_status IN ('refunded','refund_requested') FOR UPDATE",[req.params.id])).rows[0];
 if(!o||o.refund_reviewed_at){await client.query('ROLLBACK');return fail(res,409,'Refund already reviewed or missing')}
 if(decision==='reject'){
   const amount=Number(o.total_cents);
   const debit=await client.query('UPDATE users SET balance_cents=balance_cents-$1 WHERE id=$2 AND balance_cents >= $1 RETURNING id',[amount,o.user_id]);
   if(!debit.rowCount){await client.query('ROLLBACK');return fail(res,409,'Cannot reverse refund: insufficient available wallet balance. Resolve remaining dispute manually.')}
   await client.query("INSERT INTO ledger(user_id,delta_cents,kind,reference_id) VALUES($1,$2,'refund_reversal',$3)",[o.user_id,-amount,o.id]);
   await client.query('UPDATE seller_earnings SET voided_at=NULL WHERE order_item_id IN (SELECT id FROM order_items WHERE order_id=$1) AND released_at IS NULL',[o.id]);
 }
 if(decision==='approve'&&o.buyer_status==='refund_requested'){
   await client.query('UPDATE users SET balance_cents=balance_cents+$1 WHERE id=$2',[o.total_cents,o.user_id]);
   await client.query("INSERT INTO ledger(user_id,delta_cents,kind,reference_id) VALUES($1,$2,'refund',$3)",[o.user_id,o.total_cents,o.id]);
   await client.query('UPDATE seller_earnings SET voided_at=now() WHERE order_item_id IN (SELECT id FROM order_items WHERE order_id=$1)',[o.id]);
 }
 await client.query('UPDATE orders SET buyer_status=$1,refund_reviewed_at=now(),refund_reviewed_by=$2,refund_admin_message=$3 WHERE id=$4',[decision==='approve'?'refunded':'refund_rejected',req.user.id,message,o.id]);
 await client.query('COMMIT');res.json({ok:true,status:decision==='approve'?'refunded':'refund_rejected'});
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}));
app.get('/api/admin/overview',guard,roles('admin'),wrap(async(_req,res)=>{const n=await one("SELECT (SELECT count(*) FROM users)::int users,(SELECT count(*) FROM products)::int products,(SELECT count(*) FROM deposits WHERE status='pending')::int pending,(SELECT count(*) FROM orders)::int orders");res.json(n)}));
app.get('/api/admin/users',guard,roles('admin'),wrap(async(_req,res)=>res.json(await query('SELECT id,username,role,balance_cents,created_at FROM users ORDER BY id DESC'))));
app.patch('/api/admin/users/:id',guard,roles('admin'),wrap(async(req,res)=>{if(!['user','seller','admin'].includes(req.body?.role)||Number(req.params.id)===Number(req.user.id))return fail(res,400,'Invalid role change');const r=await query('UPDATE users SET role=$1 WHERE id=$2 RETURNING id',req.body.role,req.params.id);res.json({ok:!!r.length})}));
app.get('/api/admin/deposits',guard,roles('admin'),wrap(async(_req,res)=>res.json(await query("SELECT d.*,u.username,m.code,m.network FROM deposits d JOIN users u ON u.id=d.user_id JOIN payment_methods m ON m.id=d.method_id ORDER BY CASE WHEN d.status='pending' THEN 0 ELSE 1 END,d.id DESC"))));
app.patch('/api/admin/deposits/:id',guard,roles('admin'),wrap(async(req,res)=>{const status=req.body?.status;if(!['approved','rejected'].includes(status))return fail(res,400,'Invalid status');const client=await pool.connect();try{await client.query('BEGIN');const d=(await client.query("UPDATE deposits SET status=$1,processed_at=now(),processed_by=$2 WHERE id=$3 AND status='pending' RETURNING *",[status,req.user.id,req.params.id])).rows[0];if(!d){await client.query('ROLLBACK');return fail(res,409,'Deposit already processed or missing')}if(status==='approved'){await client.query('UPDATE users SET balance_cents=balance_cents+$1 WHERE id=$2',[d.amount_cents,d.user_id]);await client.query("INSERT INTO ledger(user_id,delta_cents,kind,reference_id) VALUES($1,$2,'deposit',$3)",[d.user_id,d.amount_cents,d.id])}await client.query('COMMIT');res.json({ok:true})}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}}));
app.get('/api/admin/payments',guard,roles('admin'),wrap(async(_req,res)=>res.json(await query('SELECT * FROM payment_methods ORDER BY id'))));
app.patch('/api/admin/payments/:id',guard,roles('admin'),wrap(async(req,res)=>{const address=String(req.body?.address||'').trim();if(address.length>250)return fail(res,400,'Address too long');const r=await query('UPDATE payment_methods SET address=$1,enabled=$2 WHERE id=$3 RETURNING id',address,!!req.body.enabled,req.params.id);res.json({ok:!!r.length})}));
app.post('/api/admin/categories',guard,roles('admin'),wrap(async(req,res)=>{const name=String(req.body?.name||'').trim();if(name.length<2||name.length>60)return fail(res,400,'Invalid category');const slug=name.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'')||crypto.randomUUID().slice(0,8);const r=await one('INSERT INTO categories(name,slug) VALUES($1,$2) RETURNING id',name,slug);res.json(r)}));
app.patch('/api/admin/categories/:id',guard,roles('admin'),wrap(async(req,res)=>{const name=String(req.body?.name||'').trim();if(name.length<2||name.length>60)return fail(res,400,'Invalid category');await query('UPDATE categories SET name=$1 WHERE id=$2',name,req.params.id);res.json({ok:true})}));
app.delete('/api/admin/categories/:id',guard,roles('admin'),wrap(async(req,res)=>{const client=await pool.connect();try{await client.query('BEGIN');await client.query('UPDATE products SET category_id=NULL WHERE category_id=$1',[req.params.id]);await client.query('DELETE FROM categories WHERE id=$1',[req.params.id]);await client.query('COMMIT');res.json({ok:true})}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}}));
app.get('/api/manage/products',guard,roles('admin','seller'),wrap(async(req,res)=>res.json((await query('SELECT p.*,c.name category FROM products p LEFT JOIN categories c ON c.id=p.category_id WHERE p.active=true AND ($1::boolean OR p.seller_id=$2) ORDER BY p.id DESC',req.user.role==='admin',req.user.id)).map(cost))));
const productFields=b=>{const title=String(b.title||'').trim(),description=String(b.description||'').trim(),delivery=String(b.delivery_text||'').trim(),image=String(b.image_url||'').trim(),price=Number(b.price),stock=Number(b.stock),category=Number(b.category_id)||null;if(title.length<2||title.length>150||description.length>4000||delivery.length>5000||image.length>500||!Number.isFinite(price)||price<0||price>1000000||!Number.isInteger(stock)||stock<0||stock>10000000||(image&&!/^(https:\/\/|\/assets\/|\/api\/photos\/[0-9a-f-]{36}$)/i.test(image)))throw Error('Invalid product fields');return [category,title,description,Math.round(price*100),stock,image,delivery,b.active!==false]};
app.post('/api/manage/products',guard,roles('admin','seller'),wrap(async(req,res)=>{let a;try{a=productFields(req.body)}catch(e){return fail(res,400,e.message)}const p=await one('INSERT INTO products(category_id,title,description,price_cents,stock,image_url,delivery_text,active,seller_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id',...a,req.user.id);res.json(p)}));
app.patch('/api/manage/products/:id',guard,roles('admin','seller'),wrap(async(req,res)=>{let a;try{a=productFields(req.body)}catch(e){return fail(res,400,e.message)}const p=await one('UPDATE products SET category_id=$1,title=$2,description=$3,price_cents=$4,stock=$5,image_url=$6,delivery_text=$7,active=$8 WHERE id=$9 AND ($10::boolean OR seller_id=$11) RETURNING id',...a,req.params.id,req.user.role==='admin',req.user.id);return p?res.json({ok:true}):fail(res,404,'Product missing or not yours')}));
app.delete('/api/manage/products/:id',guard,roles('admin','seller'),wrap(async(req,res)=>{const p=await one('UPDATE products SET active=false WHERE id=$1 AND ($2::boolean OR seller_id=$3) RETURNING id',req.params.id,req.user.role==='admin',req.user.id);return p?res.json({ok:true}):fail(res,404,'Product missing or not yours')}));
app.get('/api/seller/orders',guard,roles('admin','seller'),wrap(async(req,res)=>res.json(await query('SELECT oi.*,o.created_at,u.username buyer,o.id order_id FROM order_items oi JOIN orders o ON o.id=oi.order_id JOIN users u ON u.id=o.user_id WHERE ($1::boolean OR oi.seller_id=$2) ORDER BY oi.id DESC',req.user.role==='admin',req.user.id))));
app.get('/api/qr',guard,wrap(async(req,res)=>{const d=await one('SELECT address_snapshot FROM deposits WHERE id=$1 AND user_id=$2',req.query.deposit_id,req.user.id);if(!d)return fail(res,404,'Not found');res.type('png').send(await QRCode.toBuffer(d.address_snapshot,{width:260,margin:2}))}));

app.get('/api/seller/application',guard,wrap(async(req,res)=>res.json(await one('SELECT id,full_name,address,service_category,service_demo,status,created_at FROM seller_applications WHERE user_id=$1 ORDER BY id DESC LIMIT 1',req.user.id)||null)));
app.post('/api/seller/application',guard,wrap(async(req,res)=>{
  if(req.user.role!=='user')return fail(res,403,'Only customer accounts may apply');
  const {full_name,address,service_category,service_demo,usdt_network,usdt_address}=req.body||{};
  if([full_name,address,service_category,service_demo].some(v=>typeof v!=='string'||v.trim().length<3||v.length>2000)||!['TRC20','ERC20'].includes(usdt_network)||typeof usdt_address!=='string'||usdt_address.trim().length<20||usdt_address.trim().length>120)return fail(res,400,'Complete all seller details and include a demo link or description');
  const last=await one('SELECT status FROM seller_applications WHERE user_id=$1 ORDER BY id DESC LIMIT 1',req.user.id);
  if(last?.status==='pending')return fail(res,409,'Your application is already under review');
  const result=await one('INSERT INTO seller_applications(user_id,full_name,address,service_category,service_demo,usdt_network,usdt_address) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,status',req.user.id,full_name.trim(),address.trim(),service_category.trim(),service_demo.trim(),usdt_network,usdt_address.trim());
  res.json(result);
}));
app.get('/api/admin/seller-applications',guard,roles('admin'),wrap(async(req,res)=>res.json(await query('SELECT s.id,s.user_id,u.username,s.full_name,s.address,s.service_category,s.service_demo,s.usdt_network,s.usdt_address,s.status,s.created_at FROM seller_applications s JOIN users u ON u.id=s.user_id ORDER BY s.created_at DESC'))));
app.patch('/api/admin/seller-applications/:id',guard,roles('admin'),wrap(async(req,res)=>{
  const status=req.body?.status;
  if(!['approved','rejected'].includes(status))return fail(res,400,'Invalid review action');
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    const found=await client.query("SELECT id,user_id,usdt_network,usdt_address FROM seller_applications WHERE id=$1 AND status='pending' FOR UPDATE",[req.params.id]);
    if(!found.rowCount){await client.query('ROLLBACK');return fail(res,409,'Application has already been reviewed')}
    const u=await client.query('SELECT role FROM users WHERE id=$1 FOR UPDATE',[found.rows[0].user_id]);
    if(u.rows[0]?.role!=='user'){await client.query('ROLLBACK');return fail(res,409,'Applicant role has changed')}
    if(status==='approved'){await client.query("UPDATE users SET role='seller' WHERE id=$1",[found.rows[0].user_id]);if(found.rows[0].usdt_network&&found.rows[0].usdt_address)await client.query("INSERT INTO seller_payout_profiles(user_id,usdt_network,usdt_address) VALUES($1,$2,$3) ON CONFLICT(user_id) DO UPDATE SET usdt_network=EXCLUDED.usdt_network,usdt_address=EXCLUDED.usdt_address",[found.rows[0].user_id,found.rows[0].usdt_network,found.rows[0].usdt_address])}
    await client.query('UPDATE seller_applications SET status=$1,reviewed_at=now(),reviewed_by=$2 WHERE id=$3',[status,req.user.id,req.params.id]);
    await client.query('COMMIT');res.json({ok:true,status});
  }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}));

/* Persistent product photo uploads stored in PostgreSQL (Vercel has no durable local filesystem). */
app.post('/api/manage/photo',guard,roles('admin','seller'),wrap(async(req,res)=>{
  const raw=req.body?.data;
  if(typeof raw!=='string'||raw.length>2200000)return fail(res,400,'Select a JPG, PNG or WebP image under 1.5 MB');
  const match=/^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/]+={0,2})$/.exec(raw);
  if(!match)return fail(res,400,'Unsupported image format');
  const bytes=Buffer.from(match[2],'base64');
  if(!bytes.length||bytes.length>1500000)return fail(res,400,'Maximum photo size is 1.5 MB');
  const kind=match[1];
  const valid=(kind==='image/jpeg'&&bytes[0]===255&&bytes[1]===216&&bytes[2]===255)||
   (kind==='image/png'&&bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])))||
   (kind==='image/webp'&&bytes.toString('ascii',0,4)==='RIFF'&&bytes.toString('ascii',8,12)==='WEBP');
  if(!valid)return fail(res,400,'Invalid image data');
  const photo=await one('INSERT INTO product_photos(uploader_id,image_data,mime_type) VALUES($1,$2,$3) RETURNING id',req.user.id,bytes,kind);
  res.status(201).json({url:'/api/photos/'+photo.id});
}));
app.get('/api/photos/:id',wrap(async(req,res)=>{
  if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(req.params.id))return fail(res,404,'Not found');
  const p=await one('SELECT image_data,mime_type FROM product_photos WHERE id=$1',req.params.id);
  if(!p)return fail(res,404,'Photo not found');
  res.set('Cache-Control','public, max-age=86400, immutable');
  res.type(p.mime_type).send(p.image_data);
}));

/* Seller sales split is recorded at checkout: 35% platform commission, 65% seller net. All payments are manual and reviewed. */
app.get('/api/seller/finance',guard,roles('seller','admin'),wrap(async(req,res)=>{
 const totals=await one('SELECT COALESCE(SUM(gross_cents),0)::bigint gross_cents,COALESCE(SUM(commission_cents),0)::bigint commission_cents,COALESCE(SUM(net_cents),0)::bigint net_cents FROM seller_earnings WHERE seller_id=$1 AND released_at IS NOT NULL AND voided_at IS NULL',req.user.id);
 const reserved=await one("SELECT COALESCE(SUM(amount_cents),0)::bigint reserved_cents FROM seller_payout_requests WHERE seller_id=$1 AND status IN ('pending','paid')",req.user.id);
 res.json({totals,reserved_cents:reserved.reserved_cents,available_cents:Math.max(0,Number(totals.net_cents)-Number(reserved.reserved_cents)),profile:await one('SELECT usdt_network,usdt_address FROM seller_payout_profiles WHERE user_id=$1',req.user.id),requests:await query('SELECT id,amount_cents,usdt_network,usdt_address,status,txid,created_at FROM seller_payout_requests WHERE seller_id=$1 ORDER BY id DESC',req.user.id)});
}));
app.put('/api/seller/payout-profile',guard,roles('seller'),wrap(async(req,res)=>{
 const {usdt_network,usdt_address}=req.body||{};
 if(!['TRC20','ERC20'].includes(usdt_network)||typeof usdt_address!=='string'||usdt_address.trim().length<20||usdt_address.length>120)return fail(res,400,'Enter a valid USDT network and receiving address');
 await query('INSERT INTO seller_payout_profiles(user_id,usdt_network,usdt_address) VALUES($1,$2,$3) ON CONFLICT(user_id) DO UPDATE SET usdt_network=$2,usdt_address=$3,updated_at=now()',req.user.id,usdt_network,usdt_address.trim());res.json({ok:true});
}));
app.post('/api/seller/payout-requests',guard,roles('seller'),wrap(async(req,res)=>{
 const amount=numeric(req.body?.amount_cents);if(!amount)return fail(res,400,'Enter a positive payout amount');
 const client=await pool.connect();
 try{await client.query('BEGIN');await client.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[req.user.id]);
 const profile=(await client.query('SELECT * FROM seller_payout_profiles WHERE user_id=$1',[req.user.id])).rows[0];
 if(!profile){await client.query('ROLLBACK');return fail(res,400,'Configure your USDT receiving address first')}
 const totals=(await client.query('SELECT COALESCE(SUM(net_cents),0)::bigint n FROM seller_earnings WHERE seller_id=$1 AND released_at IS NOT NULL AND voided_at IS NULL',[req.user.id])).rows[0];
 const used=(await client.query("SELECT COALESCE(SUM(amount_cents),0)::bigint n FROM seller_payout_requests WHERE seller_id=$1 AND status IN ('pending','paid')",[req.user.id])).rows[0];
 if(Number(totals.n)-Number(used.n)<amount){await client.query('ROLLBACK');return fail(res,400,'Insufficient seller earnings')}
 const payout=(await client.query("INSERT INTO seller_payout_requests(seller_id,amount_cents,usdt_network,usdt_address) VALUES($1,$2,$3,$4) RETURNING id,status",[req.user.id,amount,profile.usdt_network,profile.usdt_address])).rows[0];
 await client.query('COMMIT');res.status(201).json(payout);
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}));
app.get('/api/admin/payout-requests',guard,roles('admin'),wrap(async(req,res)=>res.json(await query('SELECT p.*,u.username seller_username FROM seller_payout_requests p JOIN users u ON u.id=p.seller_id ORDER BY p.id DESC'))));
app.patch('/api/admin/payout-requests/:id',guard,roles('admin'),wrap(async(req,res)=>{
 const status=req.body?.status,txid=String(req.body?.txid||'').trim();
 if(!['paid','rejected'].includes(status)||status==='paid'&&(txid.length<8||txid.length>160))return fail(res,400,'Mark paid with a valid on-chain transaction reference, or reject');
 const p=await one("UPDATE seller_payout_requests SET status=$1,txid=$2,reviewed_at=now(),reviewed_by=$3 WHERE id=$4 AND status='pending' RETURNING id,status",status,status==='paid'?txid:null,req.user.id,req.params.id);
 if(!p)return fail(res,409,'Payout already reviewed or missing');
 res.json(p);
}));
export default app;
