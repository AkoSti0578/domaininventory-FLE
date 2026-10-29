# Domein-inventaris

Website om het script `Invoke-DomainUnjoinAssessment.ps1` te downloaden en per computer de uitkomsten te bekijken:
de risico's bij het uit het domein halen en de applicatie-inventaris (system-wide en per gebruiker).

- **Eerste start**: de website vraagt je het eerste admin-account aan te maken. Daarna is die pagina dicht.
- **Script downloaden**: het adres van de website en de upload-sleutel staan al in het gedownloade script.
- **Uitvoeren op een domeincomputer**: het script maakt lokaal het HTML-rapport en de CSV-bestanden, zoals eerst,
  en stuurt de resultaten naar de website (`POST /api/reports` met header `X-Api-Key`).
- **Overzicht**: alle computers met hun uitkomst (Risico / Waarschuwing / OK), de aantallen, het domein, het OS en het laatste rapport.
  Per computer zie je het volledige rapport, de historie (standaard de laatste 25 rapporten) en de CSV-exports.
- **Instellingen**: beheerders toevoegen of verwijderen, je wachtwoord wijzigen en de upload-sleutel vernieuwen.

## Techniek

- Node.js 22 LTS zonder externe packages (`node:http`, `node:sqlite`, `node:crypto`).
- SQLite-database in `/home/data/domaininventory`. Op App Service blijft `/home` bewaard bij herstarts en deployments.
- Wachtwoorden worden gehasht met scrypt. De sessiecookie is HttpOnly en SameSite, formulieren hebben CSRF-tokens
  en er is een rem op mislukte inlogpogingen.

### App-instellingen

| Instelling | Betekenis |
| --- | --- |
| `SETUP_TOKEN` | **Aanbevolen.** De code die je moet invullen bij het aanmaken van de eerste admin. Zonder deze code kan wie de site als eerste opent de admin aanmaken. |
| `BASE_URL` | Optioneel. Het publieke adres dat in het script komt, bijvoorbeeld `https://inventaris.example.nl`. Standaard wordt het adres gebruikt waarmee je de site opent. |
| `REPORT_RETENTION` | Optioneel. Het aantal rapporten dat per computer bewaard blijft (standaard 25). |
| `DATA_DIR` | Optioneel. De map voor de database (standaard `/home/data/domaininventory` op Azure). |
| `DISPLAY_TZ` | Optioneel. De tijdzone voor datums (standaard `Europe/Amsterdam`). |

## Uitrollen op Azure App Service (B1) vanuit de GitHub-repo met az cli

Voer dit uit in Azure Cloud Shell (Bash) of lokaal na `az login`.
De naam van de web-app moet wereldwijd uniek zijn, want hij wordt `<naam>.azurewebsites.net`.

```bash
RG=rg-domaininventory
LOCATION=westeurope
PLAN=asp-domaininventory
APP=domaininventory-$RANDOM
REPO=https://github.com/AkoSti0578/domaininventory-FLE
BRANCH=main
SETUP_TOKEN=$(openssl rand -base64 24)
echo "Web-app: $APP   Setup-code: $SETUP_TOKEN"
```

Bewaar de setup-code: die heb je nodig bij de eerste start.

Resourcegroep en App Service-plan B1 (Linux) aanmaken:

```bash
az group create --name $RG --location $LOCATION
```

```bash
az appservice plan create --name $PLAN --resource-group $RG --location $LOCATION --sku B1 --is-linux
```

De web-app aanmaken met Node 22 LTS (controleer de beschikbare runtimes met `az webapp list-runtimes --os linux`):

```bash
az webapp create --name $APP --resource-group $RG --plan $PLAN --runtime "NODE:22-lts"
```

Configuratie: startcommando, Always On, alleen HTTPS en minimaal TLS 1.2:

```bash
az webapp config set --name $APP --resource-group $RG --startup-file "node server.js" --always-on true --min-tls-version 1.2 --ftps-state Disabled --http20-enabled true
```

```bash
az webapp update --name $APP --resource-group $RG --https-only true
```

```bash
az webapp config appsettings set --name $APP --resource-group $RG --settings SETUP_TOKEN="$SETUP_TOKEN" SCM_DO_BUILD_DURING_DEPLOYMENT=true WEBSITES_ENABLE_APP_SERVICE_STORAGE=true
```

Deployment vanuit GitHub koppelen. Bij een **private** repo heb je een GitHub personal access token nodig
(classic token met de scopes `repo` en `admin:repo_hook`, zodat App Service een webhook kan zetten).
Daarna wordt elke push naar `$BRANCH` automatisch uitgerold:

```bash
az webapp deployment source config --name $APP --resource-group $RG --repo-url $REPO --branch $BRANCH --git-token <GITHUB_PAT>
```

Bij een **publieke** repo kan het ook zonder token. Dan rol je nieuwe versies handmatig uit met `sync`:

```bash
az webapp deployment source config --name $APP --resource-group $RG --repo-url $REPO --branch $BRANCH --manual-integration
```

```bash
az webapp deployment source sync --name $APP --resource-group $RG
```

De site openen en de logs volgen:

```bash
az webapp browse --name $APP --resource-group $RG
```

```bash
az webapp log tail --name $APP --resource-group $RG
```

Open `https://<APP>.azurewebsites.net`. Je komt dan op de pagina om de eerste admin aan te maken (met de setup-code).

> Let op: deploy vanaf de branch waarop deze code staat. Staat de code nog niet op `main`, zet dan `BRANCH`
> op de featurebranch of merge eerst naar `main`.

## Het script uitvoeren op een domeincomputer

1. Log in op de website, ga naar **Script downloaden** en download het script.
2. Kopieer het script naar de computer en voer het uit in **Windows PowerShell 5.1 (64-bit) als administrator**:

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Temp\Invoke-DomainUnjoinAssessment.ps1
   ```

3. Na afloop staat de computer in het overzicht.

Voor RMM of Intune kun je `-NoOpen` gebruiken. Je kunt het script ook direct van de website laden; de one-liner
staat op de downloadpagina. Gebruik `-NoUpload` om alleen het lokale rapport te maken.

De domeincomputer moet de website via HTTPS (poort 443) kunnen bereiken.

## Lokaal draaien en testen

```bash
npm start
```

```bash
npm test
```

Zonder `DATA_DIR` staat de database lokaal in `./data`.
