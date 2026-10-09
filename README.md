# Russian Shadow E-commerce

Vite/React storefront and Node API intended for Vercel with Neon PostgreSQL.

## Upload the application source

The application source package is `Russian-Shadow-Vercel-Neon-Source.zip` from the ChatGPT conversation. Extract it and upload the files inside the `russian-shadow` directory into this repository root (not the parent folder). Exclude `.env`, `node_modules` and database secrets.

## Vercel

Import `Shazi786786/russian-shadow-ecommerce` with framework Vite, build command `npm run build`, output directory `dist`.

Set `DATABASE_URL` and `JWT_SECRET` as encrypted environment variables. The separate existing Vercel project `russian-shadow-ecommerce` already has those variables configured; prefer linking this repository to that project instead of creating a duplicate.

**Deployment is not complete until all application source and design assets have been committed and the Vercel build and API tests pass.**
