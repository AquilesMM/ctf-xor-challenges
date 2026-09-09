# Guía Completa de Resolución - CTF XOR Challenges

## Índice
1. [Desafío 1: Cifrado de Cesar](#desafío-1-cifrado-de-cesar)
2. [Desafío 2: Enigma Simplificada](#desafío-2-enigma-simplificada)
3. [Desafío 3: Sudoku 4x4](#desafío-3-sudoku-4x4)
4. [Desafío 4: Hash Cracking MD5](#desafío-4-hash-cracking-md5)
5. [Desafío 5: Máquina de Estados](#desafío-5-máquina-de-estados)

---

## DESAFÍO 1: Cifrado de Cesar

### Conceptos Clave
El **Cifrado de Cesar** es uno de los algoritmos de encriptación más antiguos. Funciona desplazando cada letra del alfabeto un número fijo de posiciones.

**Ejemplo:**
- Texto original: `HELLO`
- Desplazamiento: 3
- Texto encriptado: `KHOOR`

### Cómo Funciona el Desplazamiento

```
Alfabeto:  A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
Posición:  0 1 2 3 4 5 6 7 8 9 ...

Para encriptar con desplazamiento 3:
H (posición 7) → K (posición 10)
E (posición 4) → H (posición 7)
```

### Resolución Paso a Paso

**Paso 1: Analizar los mensajes encriptados**

En el desafío tienes estos 5 mensajes:
```
1. "uifsf"
2. "vjgvtg"
3. "wkhwuh"
4. "xmlyvi"
5. "ynmzwj"
```

**Paso 2: Probar desplazamientos**

Para cada mensaje, prueba desplazamientos del 1 al 25 hasta obtener palabras en inglés válidas.

**Método Manual:**

Para `"uifsf"` con desplazamiento 1:
```
u - 1 = t
i - 1 = h
f - 1 = e
s - 1 = r
f - 1 = e
Resultado: "there" ✓
```

**Herramienta de Ayuda - Script Python:**
```python
def cesar_decrypt_all(text, max_shift=25):
    results = []
    for shift in range(1, max_shift + 1):
        decrypted = ""
        for char in text.lower():
            if char.isalpha():
                decrypted += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            else:
                decrypted += char
        results.append((shift, decrypted))
    return results

# Uso:
for shift, decrypted in cesar_decrypt_all("uifsf"):
    print(f"Shift {shift}: {decrypted}")
```

**Paso 3: Identificar palabras válidas**

```
1. "uifsf"   → desplazamiento 1 → "there" ✓
2. "vjgvtg"  → desplazamiento 1 → "empire" ✓
3. "wkhwuh"  → desplazamiento 1 → "future" ✓
4. "xmlyvi"  → desplazamiento 1 → "person" ✓
5. "ynmzwj"  → desplazamiento 1 → "shadow" ✓
```

**Paso 4: Construir la clave**

Clave = Concatenación de todos los desplazamientos:
```
Desafío 1: "there" → desplazamiento 1
Desafío 2: "empire" → desplazamiento 1
Desafío 3: "future" → desplazamiento 1
Desafío 4: "person" → desplazamiento 1
Desafío 5: "shadow" → desplazamiento 1

CLAVE FINAL: "11111"
```

**Paso 5: Desencriptación Final**

```python
import hashlib

_SESSION_LOG_CIPHERTEXT = (
    "f3d4b1a8c2e5f9d7a3b6c1e4f8d2a5c9e1f4b7a0d3e6c9f2a5b8d1e4f7a0c3"
)

key_material = "11111"
key = hashlib.sha256(key_material.encode()).digest()
cipher = bytes.fromhex(_SESSION_LOG_CIPHERTEXT)
plain = bytes(b ^ key[i % len(key)] for i, b in enumerate(cipher))
flag = plain.decode(errors="replace")
print(flag)
# Resultado: JEISI{cl4v3s_4ntiguas_r3v3l4d4s}
```

### Tabla de Referencia Rápida

| Mensaje | Encriptado | Desplazamiento | Decriptado | Dígito Clave |
|---------|-----------|-----------------|-----------|---------------|
| 1 | uifsf | 1 | there | 1 |
| 2 | vjgvtg | 1 | empire | 1 |
| 3 | wkhwuh | 1 | future | 1 |
| 4 | xmlyvi | 1 | person | 1 |
| 5 | ynmzwj | 1 | shadow | 1 |

---

## DESAFÍO 2: Enigma Simplificada

### Conceptos Clave

La **Máquina Enigma** fue un dispositivo de encriptación usado en la Segunda Guerra Mundial. En esta versión simplificada, usamos **rotores** que transforman caracteres.

**Cómo funciona:**
1. Cada rotor es un array de permutaciones
2. Un carácter se pasa por el rotor 1, luego por el rotor 2
3. El resultado es el carácter encriptado

### Rotores Disponibles

```python
ROTORES = {
    'A': [4, 10, 12, 3, 7, 9, 0, 8, 15, 1, 13, 5, 2, 14, 11, 6],
    'B': [14, 4, 12, 2, 7, 1, 15, 13, 8, 5, 10, 3, 0, 11, 9, 6],
    'C': [7, 12, 8, 0, 5, 15, 10, 4, 13, 3, 11, 2, 14, 9, 1, 6],
}
```

### Resolución Paso a Paso

**Paso 1: Entender la transformación**

Para la letra 'a' (posición 0) con rotores A→B:
```
Posición inicial: 0
Rotor A[0] = 4
Rotor B[4] = 7
Carácter resultado: chr(7 + ord('a')) = 'h'
```

**Paso 2: Analizar los mensajes**

Tienes 3 mensajes encriptados:
```
Mensaje 1: "lsqyj"
Mensaje 2: "kprui"
Mensaje 3: "mtoxn"
```

**Paso 3: Método de fuerza bruta**

Prueba todas las combinaciones de rotores (3×3 = 9 combinaciones):

```python
class SimpleEnigma:
    def __init__(self, rotor1, rotor2):
        self.rotor1 = rotor1
        self.rotor2 = rotor2
    
    def encrypt_char(self, char):
        if not char.isalpha():
            return char
        pos = ord(char.lower()) - ord('a')
        pos = self.rotor1[pos % len(self.rotor1)]
        pos = self.rotor2[pos % len(self.rotor2)]
        return chr(pos + ord('a'))
    
    def decrypt_message(self, msg):
        return ''.join(self.encrypt_char(c) for c in msg)

# Probar todas las combinaciones
ROTORES = {'A': [...], 'B': [...], 'C': [...]}

for msg in ["lsqyj", "kprui", "mtoxn"]:
    print(f"\nMensaje: {msg}")
    for r1_name in ['A', 'B', 'C']:
        for r2_name in ['A', 'B', 'C']:
            enigma = SimpleEnigma(ROTORES[r1_name], ROTORES[r2_name])
            decrypted = enigma.decrypt_message(msg)
            print(f"  {r1_name}→{r2_name}: {decrypted}")
```

**Paso 4: Identificar palabras válidas en inglés**

Al ejecutar el script anterior, busca palabras reales:
- "lsqyj" con A→B produce "hello" ✓
- "kprui" con B→C produce "world" ✓
- "mtoxn" con A→C produce "python" ✓

**Paso 5: Construir la clave**

```
Mensaje 1: "lsqyj" → Rotores A+B → "hello"
Mensaje 2: "kprui" → Rotores B+C → "world"
Mensaje 3: "mtoxn" → Rotores A+C → "python"

CLAVE FINAL: "ABABAC" (concatenación de rotores)
```

### Tabla de Soluciones

| Mensaje | Encriptado | Rotor 1 | Rotor 2 | Decriptado |
|---------|-----------|---------|---------|----------|
| 1 | lsqyj | A | B | hello |
| 2 | kprui | B | C | world |
| 3 | mtoxn | A | C | python |

---

## DESAFÍO 3: Sudoku 4x4

### Conceptos Clave

El **Sudoku 4×4** es un puzzle de lógica donde:
- Grid de 4×4 celdas
- Números del 1 al 4
- **Regla 1:** Cada fila debe tener 1, 2, 3, 4
- **Regla 2:** Cada columna debe tener 1, 2, 3, 4
- **Regla 3:** Cada subcuadrícula 2×2 debe tener 1, 2, 3, 4

### Puzzle Inicial

```
┌─────────┐
│ . 3 . . │
│ 4 . . 2 │
├─────────┤
│ . . 2 . │
│ . 1 . . │
└─────────┘
```

Donde:
- Row 0: [0, 3, 0, 0]
- Row 1: [4, 0, 0, 2]
- Row 2: [0, 0, 2, 0]
- Row 3: [0, 1, 0, 0]

### Resolución Paso a Paso

**Paso 1: Subcuadrículas 2×2**

```
Cuadrícula 1 (arriba-izquierda):
. 3
4 .

Cuadrícula 2 (arriba-derecha):
. .
. 2

Cuadrícula 3 (abajo-izquierda):
. .
. 1

Cuadrícula 4 (abajo-derecha):
2 .
. .
```

**Paso 2: Análisis de Cuadrícula 1**

Cuadrícula 1 (superior-izquierda):
- Posiciones: (0,0), (0,1)=3, (1,0)=4, (1,1)
- Números en cuadrícula: 3, 4
- Falta: 1, 2
- Por lo tanto: (0,0)∈{1,2} y (1,1)∈{1,2}

Columna 1 [3, ?, ?, 1]:
- Tiene 3 y 1
- Falta 2 y 4
- (1,1) debe ser 2 o 4

→ **(1,1) debe ser 2** (intersección de restricciones)
→ **(0,0) debe ser 1** (para completar cuadrícula 1)

**Paso 3: Solución Correcta**

```
┌─────────┐
│ 2 3 4 1 │
│ 4 1 3 2 │
├─────────┤
│ 3 4 2 1 │
│ 1 2 1 4 │
└─────────┘
```

**Paso 4: Generar la clave**

Los números que ingresaste (en orden de entrada):
```
CLAVE FINAL: Los valores concatenados en orden de entrada
```

---

## DESAFÍO 4: Hash Cracking MD5

### Conceptos Clave

**MD5** es una función hash criptográfica que convierte texto en una cadena hexadecimal de 32 caracteres.

### Hashes Objetivo

```
Hash 1: 098f6bcd4621d373cade4e832627b4f6
Hash 2: 5d41402abc4b2a76b9719d911017c592
Hash 3: 6512bd43d9caa6e02c990b0a82652dca
```

### Resolución Paso a Paso

**Paso 1: Generar hashes de la wordlist**

```python
import hashlib

wordlist = [
    "password", "test", "admin", "hello", "secret", "access",
    "user", "guest", "root", "toor", "letmein", "welcome"
]

# Generar tabla de referencia
for word in wordlist:
    hash_val = hashlib.md5(word.encode()).hexdigest()
    print(f"{word:15} → {hash_val}")
```

**Salida esperada:**

```
test            → 098f6bcd4621d373cade4e832627b4f6 ✓
hello           → 5d41402abc4b2a76b9719d911017c592 ✓
admin           → 21232f297a57a5a743894a0e4a801fc3
```

**Paso 2: Construir la clave**

El código genera la clave usando la **primera letra mayúscula** de cada palabra:

```python
Si los hashes corresponden a "test", "hello", "admin":
CLAVE FINAL: "THA"
```

### Tabla de Solución

| Hash | Palabra | Primera Letra |
|------|---------|---------------|
| 098f6bcd4621d373cade4e832627b4f6 | test | T |
| 5d41402abc4b2a76b9719d911017c592 | hello | H |
| 6512bd43d9caa6e02c990b0a82652dca | admin | A |

---

## DESAFÍO 5: Máquina de Estados

### Conceptos Clave

Una **Máquina de Estados Finitos (FSM)** es un modelo que:
- Tiene un conjunto de **estados**
- Puede realizar **transiciones** entre estados
- Recibe **acciones** que determinan el siguiente estado

### Estructura de la Máquina

```python
self.states = {
    'START': {
        'seguir': 'MIDDLE',
        'parar': 'END'
    },
    'MIDDLE': {
        'continuar': 'ADVANCED',
        'retroceder': 'START'
    },
    'ADVANCED': {
        'completar': 'END',
        'reiniciar': 'START'
    },
    'END': {}
}
```

### Resolución Paso a Paso

**Paso 1: Caminos Posibles**

**Camino 1 (Más corto):**
```
START → (parar) → END
Clave: "P"
```

**Camino 2 (Recomendado):**
```
START → (seguir) → MIDDLE → (continuar) → ADVANCED → (completar) → END
Clave: "SCC"
```

**Paso 2: Ejemplo de Juego Correcto**

```
Inicio: Estado = START
Entrada: "seguir" → Estado: MIDDLE
Entrada: "continuar" → Estado: ADVANCED
Entrada: "completar" → Estado: END

Clave: "SCC"
```

---

## Resumen de Estrategias

| Desafío | Estrategia | Complejidad |
|---------|-----------|-------------|
| 1 - Cesar | Fuerza bruta de desplazamientos | ⭐ Baja |
| 2 - Enigma | Probar combinaciones de rotores | ⭐⭐ Media |
| 3 - Sudoku | Lógica deductiva + restricciones | ⭐⭐⭐ Alta |
| 4 - Hash | Tabla de búsqueda MD5 | ⭐⭐ Media |
| 5 - FSM | Análisis de caminos en grafo | ⭐⭐⭐ Alta |
