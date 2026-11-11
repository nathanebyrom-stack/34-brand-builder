# 34 Brand Builder: personal client links

- `index.html` – the Brand Builder. Opens from a personal link (`?k=…`, locks to the first device that opens it) or from a sign-in session handed over by the client area at 34automation.co.uk/clients/ (`#s=…`, lasts 12 hours, moves the device lock to the device that opens it). Saves progress online and closes after the client sends it.
- `admin.html` – private page for Nathan: create links, see who has opened or sent theirs, view answers, reset a device, issue a new link, extend, switch off, delete, and set / reset / remove each client's username and password (the password is shown once).
- Back end: Supabase project "34 Brand Builder" (eu-west-2), edge function `brand-builder` (source in `supabase/functions/brand-builder`). Tables are locked; only the function reads or writes them. Only a SHA-256 fingerprint of each link and each sign-in session is stored; passwords are stored only as salted PBKDF2-SHA-256 hashes. Five wrong passwords in 15 minutes pause that username (and that IP address) for 15 minutes. Schema changes live in `supabase/migrations`.

The public free preview at the repo root (`/index.html`) is separate and unchanged.
