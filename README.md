# Russian Shadow — Full-stack E-commerce Marketplace

Dark hacker/spy style marketplace based on the approved visual preview. The original preview is included at `client/public/assets/original-design-preview.png`; extracted hero/product art is included in `client/public/assets`.

## Included
- Responsive storefront: home, featured products, searchable catalog, sidebar categories, cart, checkout.
- Username/password registration and login, bcrypt password hashing, httpOnly cookie tokens.
- User dashboard, wallet balance, purchase history, deposit history and purchase delivery instructions.
- Admin dashboard: approve/reject submitted deposits, edit BTC / USDT TRC20 / ETH / USDT ERC20 payment addresses, enable/disable coins, manage categories and user roles.
- Seller/admin product CRUD: title, description, category, price, stock, photo URL, digital delivery instructions. Seller sees orders related to their products.
- USD-denominated internal balances; manual cryptocurrency deposits with QR address and 30-minute payment window.
- Atomic checkout and inventory reduction; transaction ledger and duplicate-approval prevention.
- Seed demo categories and starter product examples (can be edited from seller panel).

## Run locally (Node.js 22 recommended)
1. Install Node.js 22+ and build prerequisites (C++ compiler needed for `better-sqlite3` on platforms without prebuilt binaries).
2. At the project root run `npm install`.
3. The project ships with `.env` generated for local first boot. Review/reset the administrator and seller password before deployment; put strong unique values in production.
4. Run `npm run dev`.
5. Open **http://localhost:5173**.
6. Log in with the administrator credentials in the root `.env`; set each of the four receiving wallet addresses in **Admin Panel → Payments**. No wallet address is configured by default, so users cannot request deposits before configuration.
7. To add a seller, register an account, then sign in as admin and change that user's role to `seller` from Admin Panel → Users. Seller panel will then become visible.

## Production run
- `npm run build`
- `npm start`
- Host `PORT` from `.env` (defaults to 4000); serves built frontend and backend.
- Set `NODE_ENV=production` only behind HTTPS for secure cookies.
- Keep the SQLite file in persistent storage. Do not store it on ephemeral serverless storage.
- Change `JWT_SECRET`, passwords, and use HTTPS. Do not reuse the sample credentials in production.
- Payment deposits are **manual verification only**. The system does not verify crypto payments on-chain, determine exchange rates, or automate payments. The administrator is responsible for verifying correct amount, network, recipient and confirmations before approval.
- Product delivery information is shown in Purchase History after checkout. For physical products the seller fulfils shipment separately; shipping automation is not included.
- Product images can be supplied as public HTTPS links or from `/assets`.
- Balances are USD-denominated reference values; USDT and other crypto deposits are not automatically converted.

## Architecture
- Express REST API: `server/index.js`
- SQLite: `data/russian-shadow.sqlite` (created at first boot)
- React/Vite frontend: `client/src/main.jsx`, `client/src/style.css`
- Seed fixtures: created on the first boot; admin and seller users via `.env`.

## API functionality
- `/api/auth/*` registration/login/logout
- `/api/me`, `/api/products`, `/api/categories`, `/api/orders`, `/api/wallet`
- `/api/payments`, `/api/deposits`, `/api/deposits/:id/submit`, `/api/qr`
- `/api/admin/{deposits,payments,categories,users,overview}`
- `/api/manage/products`, `/api/seller/orders`

No banking, blockchain node, email delivery, automatic payouts, or crypto processing provider integration is bundled.
