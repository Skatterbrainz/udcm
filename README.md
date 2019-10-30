# udcm

Universal Dashboard Configuration Manager Stuff with French Fries and a Drink

## Examples

```powershell
New-UDCM -SiteCode "P01"
```

Then from the same CM site server, query the web service

```powershell
Invoke-RestMethod -Uri "http://localhost:10001/api/cmdevices"
```
or from a different computer...

```powershell
Invoke-RestMethod -Uri "http://cm01:10001/api/cmusers"
```
