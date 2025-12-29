# Endpoint Hunter 🕵️‍♂️

**Endpoint Hunter** és una extensió per a Firefox dissenyada per detectar i analitzar endpoints i paràmetres d’aplicacions web mentre navegues per elles.

Està pensada com a eina d’ajuda per a:
- Pentesting autoritzat
- Bug bounty
- Formació en seguretat web
- Anàlisi d’aplicacions web modernes

---

## 🚀 Funcionalitats

- 🔍 Detecció automàtica d’endpoints GET i POST
- 🧠 Identificació d’endpoints potencialment sensibles
- 🎯 Filtre per mostrar només endpoints sensibles
- 📋 Còpia d’un endpoint individual
- 📋 Còpia de tots els endpoints visibles
- 📤 Exportació d’endpoints en format JSON
- 📊 Comptador de hits per endpoint

---

## 🧪 Exemples d’ús

- Identificar rutes ocultes en aplicacions SPA
- Detectar formularis de login o endpoints d’autenticació
- Analitzar paràmetres interessants per testing manual
- Preparar endpoints per importar-los a Burp, Postman o altres eines

---

## ⚠️ Disclaimer

> Aquesta extensió està pensada **únicament** per a finalitats educatives i per a proves de seguretat **autoritzades**.
>
> L’ús d’aquesta eina contra aplicacions sense permís explícit pot ser il·legal.
> L’autor no es fa responsable de l’ús indegut del programari.

---

## Captures de pantalla

### Popup amb endpoints detectats amb informació sensible
![Popup](screenshots/endpoints-sensible.png)

### Exportant al portaretalls del sistema
![Export & copy](screenshots/export-copy.png)

## 🛠 Instal·lació (desenvolupament)

1. Clona el repositori:
   ```bash
   git clone https://github.com/carlesreig/endpoint-hunter.git

2. Obre Firefox i ves a:

    ``
    about:debugging#/runtime/this-firefox

2. Carrega  `manifest.json`

## 🤝 Contribucions

Les contribucions són benvingudes!
Obre un Issue per bugs o propostes.
Fes un Pull Request per noves funcionalitats.
Marca els canvis de manera clara.

## 📄 Llicència

![Mozilla Public License Version 2.0](https://www.mozilla.org/en-US/MPL/2.0/) (MPL 2.0)
