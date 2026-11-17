// XONI-WEB 2026 - Interactividad de la interfaz web

document.addEventListener('DOMContentLoaded', function(){
  // Extraer URLs automaticamente al pegar en el textarea
  const textarea = document.querySelector('textarea[name="urls"]');
  if (textarea) {
    textarea.addEventListener('paste', function(e){
      const texto = (e.clipboardData || window.clipboardData).getData('text');
      if (!texto) return;
      const urls = extraerURLs(texto);
      if (urls.length) {
        e.preventDefault();
        const actual = textarea.value;
        const separador = actual && !actual.endsWith('\n') ? '\n' : '';
        textarea.value = actual + separador + urls.join('\n');
        textarea.dispatchEvent(new Event('input'));
      }
    });
  }

  // Contador en vivo de URLs detectadas en el textarea
  const contadorUrls = document.getElementById('contadorUrls');
  if (textarea && contadorUrls) {
    const actualizarContador = function(){
      const n = extraerURLs(textarea.value).length;
      contadorUrls.textContent = n === 1 ? '1 URL detectada' : n + ' URLs detectadas';
    };
    textarea.addEventListener('input', actualizarContador);
    actualizarContador();
  }

  // Boton de analizar: desactivar mientras se envia para evitar doble envio
  const form = document.querySelector('form[action*="analizar"]');
  if (form) {
    form.addEventListener('submit', function(){
      const btn = form.querySelector('button[type="submit"]');
      if (btn) {
        btn.disabled = true;
        btn.textContent = 'Analizando...';
      }
    });
  }

  // Zona de subida de archivo: mostrar nombre del archivo seleccionado
  const inputArchivo = document.getElementById('archivo');
  if (inputArchivo) {
    inputArchivo.addEventListener('change', function(){
      const lbl = document.getElementById('nombreArchivo');
      if (lbl && this.files && this.files[0]) {
        lbl.textContent = this.files[0].name;
      }
    });
  }

  // Vista previa: contador de seleccionados + seleccionar todos / ninguno
  const listaEnlaces = document.getElementById('listaEnlaces');
  if (listaEnlaces) {
    const contadorSel = document.getElementById('contadorSel');
    const checksPrev = () => Array.from(listaEnlaces.querySelectorAll('input[type="checkbox"]'));
    const actualizarSel = () => {
      const todos = checksPrev();
      const sel = todos.filter(c => c.checked).length;
      if (contadorSel) contadorSel.textContent = sel + ' de ' + todos.length + ' seleccionados';
    };
    listaEnlaces.addEventListener('change', actualizarSel);
    actualizarSel();
    const btnTodos = document.getElementById('btnTodos');
    const btnNinguno = document.getElementById('btnNinguno');
    if (btnTodos) btnTodos.addEventListener('click', function() {
      checksPrev().forEach(c => { c.checked = true; });
      actualizarSel();
    });
    if (btnNinguno) btnNinguno.addEventListener('click', function() {
      checksPrev().forEach(c => { c.checked = false; });
      actualizarSel();
    });
  }
});

function extraerURLs(texto) {
  const re = /https?:\/\/[^\s<>"'\)]+/gi;
  const urls = [];
  let m;
  while ((m = re.exec(texto)) !== null) {
    let u = m[0].replace(/[.,;:!?)\]}$]+$/, '');
    if (!urls.includes(u)) urls.push(u);
  }
  // lineas que sean solo dominio (sin protocolo)
  texto.split('\n').forEach(function(linea){
    linea = linea.trim();
    if (!linea || linea.startsWith('#')) return;
    if (linea.startsWith('http://') || linea.startsWith('https://')) return;
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(\/.*)?$/.test(linea) && !linea.includes(' ')) {
      const u = 'https://' + linea;
      if (!urls.includes(u)) urls.push(u);
    }
  });
  return urls;
}

// Subida de archivo por AJAX: extrae URLs y las anade al textarea
function subirArchivo(input) {
  const archivo = input.files && input.files[0];
  if (!archivo) return;
  const formData = new FormData();
  formData.append('archivo', archivo);
  const btn = input.form && input.form.querySelector('button[type="submit"]');
  fetch('/upload', { method: 'POST', body: formData })
    .then(r => r.json())
    .then(data => {
      if (data.ok && data.urls && data.urls.length) {
        const textarea = document.querySelector('textarea[name="urls"]');
        if (textarea) {
          const actual = textarea.value;
          const separador = actual && !actual.endsWith('\n') ? '\n' : '';
          textarea.value = actual + separador + data.urls.join('\n');
          textarea.dispatchEvent(new Event('input'));
        }
        const aviso = document.getElementById('avisoUpload');
        if (aviso) {
          aviso.textContent = 'Se extrajeron ' + data.total + ' URL(es) de ' + data.archivo + '.';
          aviso.style.display = 'block';
        }
        input.value = '';
      } else {
        const aviso = document.getElementById('avisoUpload');
        if (aviso) {
          aviso.textContent = 'No se pudieron extraer URLs de ese archivo.';
          aviso.style.display = 'block';
        }
      }
    })
    .catch(err => {
      console.error(err);
      const aviso = document.getElementById('avisoUpload');
      if (aviso) {
        aviso.textContent = 'Error al procesar el archivo.';
        aviso.style.display = 'block';
      }
    });
}
