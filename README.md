<img width="1280" height="640" alt="header github" src="https://github.com/user-attachments/assets/a68d8ba9-77af-4a71-b8c1-69f6b94c82ec" />

# Endpoint Hunter 🕵️‍♂️

**Endpoint Hunter** is a Firefox extension designed to detect and analyze web application endpoints and parameters while you browse them. You just need to visit a website and enable the extension; endpoints will automatically appear. You can filter them using the search bar or smart tags and export everything with a single click.

It is intended as a support tool for:
- 🔒 Authorized pentesting
- 🐞 Bug bounty
- 🔒 Ethical hackers
- 🛡️ Web security training
- 🌐 Modern web application analysis

---

## 🚀 Features

- 🖥️ Integrated, non-intrusive browser interface (devtools panel)
- 🪶 Lightweight, no impact on browser performance  
- 🎁 Automatic detection of GET and POST endpoints (headers) 
- 🚩 Identification of potentially sensitive endpoints  
- 🎯 Filter to show only sensitive endpoints and/or same-domain endpoints  
- 🏷️ Automatic endpoint tagging, result filtering  
- 🔍 Search detected endpoints by concept and parameters  
- 📋 Copy a single endpoint  
- 📋 Copy all visible endpoints  
- 📤 Export endpoints in JSON format  
- 📊 Hit counter per endpoint  

---

## 🧪 Use cases

- Identify hidden routes in SPA applications  
- Detect login forms or authentication endpoints  
- Analyze interesting parameters for manual testing  
- Enumeration of hidden links (routes) and HTTP methods  
- Prepare endpoints to import into Burp or other tools to detect vulnerabilities such as Dalfox or Nuclei  

---

## ⚠️ Disclaimer

> This extension is intended **only** for educational purposes and **authorized** security testing.
>
> Using this tool against applications without explicit permission may be illegal.  
> The author is not responsible for any misuse of the software.

---

## Screenshots

### Dark mode
![dark mode](screenshots/dark-mode.png) ![light mode](screenshots/light-mode.png)

### Detected endpoints with sensitive information
![interesting endpoints](screenshots/endpoints-sensible.png)

### Detected endpoints with sensitive info from the same domain
![endpoints from domain](screenshots/endpoints-sensible-domain.png)

### Endpoint filters by potential vulnerability
![vulns](screenshots/filter-endpoints-tags.png) ![TAGs](screenshots/filter-endpoints-tags2.png)

### Searching for concepts in detected endpoints
![Search filter](screenshots/find-endpoints.png)

### Exporting to the system clipboard
![Export & copy](screenshots/export-copy.png)

---

## 🛠 Installation (development)
1. Clone the repository:
   ```bash
   git clone https://github.com/carlesreig/endpoint-hunter.git

2. Open Firefox and go to:
    ```bash
    about:debugging#/runtime/this-firefox

3. Load  `manifest.json`

4. Press <kbd>F12</kbd> or <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>I</kbd> to open `Developer Tools` and select the “Endpoint Hunter” extension..

## 🤝 Contributions

Contributions are welcome!
Open an Issue for bugs or suggestions.
Submit a Pull Request for new features.
Clearly document your changes.
