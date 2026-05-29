# pki-watch

Monitor d'expiration de certificats X.509. Le projet est pense pour une equipe
infrastructure qui doit surveiller des endpoints TLS publics, des fichiers PEM
internes et declencher une alerte avant incident.

## Fonctionnalites

- Controle d'endpoints TLS (`example.com:443` ou URL HTTPS).
- Controle de fichiers PEM locaux.
- Seuils `warning` et `critical` configurables.
- Sortie table lisible ou JSON pour CI/CD.
- Webhook compatible Slack/Teams via payload JSON simple.
- Un seul binaire Go, sans dependance externe.

## Installation

```bash
go build -o pki-watch ./cmd/pki-watch
```

## Exemples

```bash
./pki-watch -target focsa.pro -warn 30 -critical 7
./pki-watch -target https://github.com -json
./pki-watch -file ./certs/internal.pem -webhook "$WEBHOOK_URL"
```

## Modele de severite

- `ok` : le certificat expire apres le seuil warning ;
- `warning` : expiration dans moins de `warn` jours ;
- `critical` : expiration dans moins de `critical` jours ou certificat deja expire.

## Tests

```bash
go test ./...
```

## Choix de conception

Pour la surveillance d'expiration, le handshake TLS est volontairement effectue
sans validation de chaine. Cela permet de remonter la date d'expiration meme
pour un certificat interne ou auto-signe. Le projet ne remplace pas un controle
PKI complet : il cible le risque operationnel d'expiration non anticipee.

