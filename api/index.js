import app from '../server/app.js';
export default function handler(req,res){
  const u=new URL(req.url,'http://localhost');
  const route=u.searchParams.get('route');
  if(route!==null){u.searchParams.delete('route');req.url='/api/'+route+(u.search||'')}
  return app(req,res);
}
