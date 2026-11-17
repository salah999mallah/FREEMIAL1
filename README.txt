WISP LIVE: setup (about 10 minutes)

1. Create a NEW API key at smtp.dev (API Keys page) and revoke the one you pasted in chat.
2. Put this whole folder on GitHub, then in Netlify choose "Add new site > Import from Git" and select it.
   (Or drag the folder onto app.netlify.com/drop. Git is better because the function is built on deploy.)
3. In Netlify: Site configuration > Environment variables, add:
     SMTPDEV_API_KEY = your new smtplabs_... key
     SIGNING_SECRET  = any long random string (e.g. 40+ random characters)
4. Redeploy. Open your site; an address is created on load.

Notes
- The key lives only in the Netlify function. It never reaches the browser.
- Each address is deleted when its timer ends (or when you press New address).
  Abandoned tabs are cleaned up the next time anything uses an expired token; for strict cleanup,
  add a Netlify scheduled function that deletes old accounts.
- Domains shown in the dropdown are the active domains on your smtp.dev account.
