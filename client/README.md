# 34 Brand Builder: personal client links

- `index.html` – the Brand Builder. Opens only from a personal link (`?k=…`), locks to the first device that opens it, saves progress online, and closes after the client sends it.
- `admin.html` – private page for Nathan: create links, see who has opened or sent theirs, view answers, reset a device, issue a new link, extend, switch off, delete.
- Back end: Supabase project "34 Brand Builder" (eu-west-2), edge function `brand-builder` (source in `supabase/functions/brand-builder`). Tables are locked; only the function reads or writes them. Only a SHA-256 fingerprint of each link is stored.

The public free preview at the repo root (`/index.html`) is separate and unchanged.
