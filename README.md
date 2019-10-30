# udcm

Universal Dashboard Configuration Manager Stuff with French Fries and a Drink

## Examples

### Launching the Web Service

```powershell
New-UDCM -SiteCode "P01"
```
Launches it on the localhost using port 10001

```powershell
New-UDCM -SiteCode "P01" -DbHost "db101" -Port 8080
```
Launches it on localhost using port 8080, using remote SQL instance

### Testing Results

Then from the same CM site server, query the web service

```powershell
Invoke-RestMethod -Uri "http://localhost:10001/api/cmdevices"
```
or from a different computer (cm01 is an example site server name)...

```powershell
Invoke-RestMethod -Uri "http://cm01:10001/api/cmusers"
```

```powershell
Invoke-RestMethod -Uri "http://cm01:10001/api/cmapps"
```