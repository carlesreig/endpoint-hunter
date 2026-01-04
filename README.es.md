🌍 **Idioma**:  
[English](README.md) · [Català](README.ca.md) · [Español](README.es.md)

# Endpoint Hunter 🕵️‍♂️

**Endpoint Hunter** es una extensión para Firefox diseñada para detectar y analizar endpoints y parámetros de aplicaciones web mientras navegas por ellas. Solo tienes que visitar la página web y activar la extensión; verás cómo los endpoints aparecen de forma automática. Podrás filtrarlos mediante el buscador o las etiquetas inteligentes y exportarlos con un solo clic.

Está pensada como una herramienta de apoyo para:
- 🔒 Pentesting autorizado  
- 🐞 Bug bounty  
- 🛡️ Formación en seguridad web  
- 🌐 Análisis de aplicaciones web modernas  

---

## 🚀 Funcionalidades

- 🖥️ Interfaz integrada en el navegador, no intrusiva  
- 🪶 Ligera, no afecta al rendimiento del navegador web  
- 🎁 Detección automática de endpoints GET y POST  
- 🚩 Identificación de endpoints potencialmente sensibles  
- 🎯 Filtro para mostrar solo endpoints sensibles y/o del mismo dominio  
- 🏷️ Etiquetas automáticas en endpoints, filtrado de resultados  
- 🔍 Buscador de endpoints detectados por concepto y parámetros  
- 📋 Copia de un endpoint individual  
- 📋 Copia de todos los endpoints visibles  
- 📤 Exportación de endpoints en formato JSON  
- 📊 Contador de hits por endpoint  

---

## 🧪 Ejemplos de uso

- Identificar rutas ocultas en aplicaciones SPA  
- Detectar formularios de login o endpoints de autenticación  
- Analizar parámetros interesantes para testing manual  
- Enumeración de enlaces ocultos (rutas) y métodos HTTP  
- Preparar endpoints para importarlos en Burp u otras herramientas para detectar vulnerabilidades como Dalfox o Nuclei  

---

## ⚠️ Disclaimer

> Esta extensión está pensada **únicamente** para fines educativos y para pruebas de seguridad **autorizadas**.
>
> El uso de esta herramienta contra aplicaciones sin permiso explícito puede ser ilegal.  
> El autor no se hace responsable del uso indebido del software.

---

## Capturas de pantalla

### Dark mode
![dark mode](screenshots/dark-mode.png) ![light mode](screenshots/light-mode.png)

### Endpoints detectados con información sensible
![interesting endpoints](screenshots/endpoints-sensible.png)

### Endpoints detectados con información sensible y del mismo dominio
![endpoints from domain](screenshots/endpoints-sensible-domain.png)

### Filtros de endpoints según posible vulnerabilidad
![vulns](screenshots/filter-endpoints-tags.png) ![TAGs](screenshots/filter-endpoints-tags2.png)

### Buscando conceptos en endpoints encontrados
![Search filter](screenshots/find-endpoints.png)

### Exportando al portapapeles del sistema
![Export & copy](screenshots/export-copy.png)

---

1. Clona el repositoroi:
   ```bash
   git clone https://github.com/carlesreig/endpoint-hunter.git

2. Abre Firefox y ve a:
    ```bash
    about:debugging#/runtime/this-firefox

3. Carga  `manifest.json`

4. Pulsa <kbd>F12</kbd> o bién <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>I</kbd> para abrir las `Developer Tools` y selecciona la extensión "Endpoint Hunter".

## 🤝 Contribucions

¡Las contribuciones son bienvenidas!
Abre un Issue para bugs o propuestas.
Haz un Pull Request para nuevas funcionalidades.
Marca los cambios de forma clara.
