# web-recon-toolkit

Lightweight scripts for passive reconnaissance during authorized bug bounty work.
No active scanning, no exploitation — just reading public sources.

## recon.py

Passive subdomain enumeration via Certificate Transparency logs (crt.sh).

```bash
python3 recon.py example.com > subdomains.txt
python3 recon.py example.com --exclude dev,staging > prod_only.txt
```

What it does:

- queries crt.sh for historical certificate names matching the domain
- deduplicates and strips wildcards
- `--exclude` throws out everything containing any of the comma-separated bits
  (env names, legacy hosts — whatever pollutes your list)
- refuses to run against non-public domains and anything resolving to
  private / loopback / link-local addresses

Useful right before you pipe the list into `httpx` or `nuclei` — the classic
first step of a bug bounty recon chain.

## Why the strict validation

The script embeds the target only into a query for a hardcoded HTTPS endpoint
and bails out on internal network names. Partly paranoia, partly a good habit:
tools you write for security work should be safe by default.

## Disclaimer

Only run this against domains you are explicitly authorized to test.
Passive CT lookups are harmless, but your subsequent scanning might not be.

## License

MIT
