## Description
CVE info extractor: use NVD CPE api to retrieve CVES(by using version number, product name...) and use openCVE api to fetch CVE details. (OpenCVE is faster than NVD Api but dont provide products version number researsh)

## Volumes
```sh
./CVE_extractor/OPSTools.json:/home/OPSTools.json
./CVE_extractor/config.json:/home/config.json
```

## config.json
```json
{
    "date": null, // [OPTIONAL] -> use back_in_time option when is null
    "back_in_time": 10, // [OPTIONAL] searsh for cve vuln for last days precised -> default=7
    "severity": ["MEDIUM", "HIGH"], // [OPTIONAL] -> default=no filters
    "opencve_user" : "xxxxxx",
    "opencve_password" : "xxxxxx",
    "path" : "/home/OPSTools.json" // [OPTIONAL] -> default=/home/OPSTools.json
}
```

## OPSTools.json
```json
[{
    "vendor": "docker",
    "tool": "docker",
    "version": ["19.03.13", "20.10.2", "20.10.3", "20.10.6"], //multiple versions
    "sys_type" : "a" // sys_type -> a/o/h (a = app / o = os / h = hardware)
},
{
    "vendor": "centos",
    "tool": "centos",
    "version": ["7.9.2009"],
    "sys_type" : "o"
}]
```

## Logs Format 
DATE CPE CVE CVVS_version severity severity_number attackvector link
  - 2018-08-13 cpe:2.3:a:docker:docker:1.6 N/A N/A N/A N/A https://www.opencve.io/cve/CVE-2015-3627
  - 2021-01-05 cpe:2.3:a:docker:docker:1.6 cvvs3 HIGH 2.1 LOCAL https://www.opencve.io/cve/CVE-2016-3697

## Run
```sh
docker-compose up --build -d && docker logs -f cve_extractor
```

## Next features
- adding deepweb cve bdd
- ajouter un check de la depreciation des cpes au lancement du script
- ameliorer la reconnaissance des cpes avec l'api opencve ex ->https://www.opencve.io/api/vendors/mysql/products/mysql/cve
- revoir gestion erreur -> repeat nvd api: il peut n'y avoir aucun cves pour un cpe
- automation
