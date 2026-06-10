// Release configuration — update this file for each release.
// setup.html reads this; no other file needs editing to add/update connectors.

const BISET_URLS = {
  // GitHub repo — used for connector download URLs.
  github_repo: 'yno9/biset',

  // Connectors shown on the connector selection screen.
  connectors: [
    {
      id:      'biset-imap',
      label:   'External Mail',
      sub:     'IMAP & SMTP',
      checked: true,
    },
    {
      id:    'biset-claude',
      label: 'Claude',
      sub:   'Claude Code conversations',
    },
  ],
}
