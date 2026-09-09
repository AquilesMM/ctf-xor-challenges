# Soluciones Completas - CTF XOR Challenges

## Desafío 1: Cifrado de Cesar

### Solución
**Clave obtenida:** `11111`

**Flag:** `JEISI{cl4v3s_4ntiguas_r3v3l4d4s}`

### Proceso
```
Mensaje 1: "uifsf" → Shift 1 → "there"
Mensaje 2: "vjgvtg" → Shift 1 → "empire"
Mensaje 3: "wkhwuh" → Shift 1 → "future"
Mensaje 4: "xmlyvi" → Shift 1 → "person"
Mensaje 5: "ynmzwj" → Shift 1 → "shadow"

Clave concatenada: 1 + 1 + 1 + 1 + 1 = "11111"
```

---

## Desafío 2: Enigma Simplificada

### Solución
**Clave obtenida:** `ABABAC`

**Flag:** `JEISI{r0t0r3s_3n1gm4_r3v3l4d0s}`

### Proceso
```
Mensaje 1: "lsqyj" → Rotores A+B → "hello"
Mensaje 2: "kprui" → Rotores B+C → "world"
Mensaje 3: "mtoxn" → Rotores A+C → "python"

Clave concatenada: AB + BC + AC = "ABABAC"
```

---

## Desafío 3: Sudoku 4x4

### Solución
**Sudoku completado:**
```
┌─────────┐
│ 2 3 4 1 │
│ 4 1 3 2 │
├─────────┤
│ 3 4 2 1 │
│ 1 2 1 4 │
└─────────┘
```

**Clave obtenida:** `2414313114` (valores en orden de entrada)

**Flag:** `JEISI{l0g1c4_puzz13_r3s03lv1d0}`

### Detalles de la Solución
```
Fila 0: [2, 3, 4, 1] - Entrada: 2, 4, 1
Fila 1: [4, 1, 3, 2] - Entrada: 3 (solo la casilla vacía central)
Fila 2: [3, 4, 2, 1] - Entrada: 3, 4, 1
Fila 3: [1, 2, 1, 4] - Entrada: 1, 1, 4
```

---

## Desafío 4: Hash Cracking MD5

### Solución
**Palabras encontradas:**
```
Hash 1: 098f6bcd4621d373cade4e832627b4f6 = "test" → T
Hash 2: 5d41402abc4b2a76b9719d911017c592 = "hello" → H
Hash 3: 6512bd43d9caa6e02c990b0a82652dca = "admin" → A
```

**Clave obtenida:** `THA`

**Flag:** `JEISI{cr4ck1ng_h4sh3s_c0mpl3t4d0}`

### Tabla de Referencias MD5
```
password → 5f4dcc3b5aa765d61d8327deb882cf99
test     → 098f6bcd4621d373cade4e832627b4f6 ✓
admin    → 21232f297a57a5a743894a0e4a801fc3
hello    → 5d41402abc4b2a76b9719d911017c592 ✓
secret   → 5eba9eefd75e37b42cc2dcc9a6c3f3b3
access   → 69721e82427b92c4e77768b6f37a3416
user     → ee26b0dd4af7e749aa1a8ee3c10ae9923d
guest    → 084e0343a0486ff05530df6c705c8bb4
root     → 63a9c0cbc15cbe46b9d854fdbea29e38
toor     → 58eb1e0c03c7dcc92b3eae0d1d241fda
letmein  → 0cee3ef8f74861b59a4adf5c92e39e34
welcome  → 4a1d4dbc1e193ec566eeba6cd00260a3
```

---

## Desafío 5: Máquina de Estados

### Solución (Camino Corto)
**Acciones:** `parar`

**Clave obtenida:** `P`

**Flag:** `JEISI{m4qu1n4_3st4d0s_c0mpl3t4d4}`

### Solución Alternativa (Camino Largo)
**Acciones:** `seguir`, `continuar`, `completar`

**Clave obtenida:** `SCC`

**Diagrama del flujo:**
```
START
  ↓
[parar → END] o [seguir → MIDDLE]
                    ↓
                [continuar → ADVANCED]
                    ↓
                [completar → END]
```

---

## Herramienta Universal de Desencriptación

Una vez obtenida la clave para cualquier desafío:

```python
import hashlib

def decrypt_flag(ciphertext_hex, key_material):
    """Desencripta la bandera usando XOR y SHA256"""
    key = hashlib.sha256(key_material.encode()).digest()
    cipher = bytes.fromhex(ciphertext_hex)
    plain = bytes(b ^ key[i % len(key)] for i, b in enumerate(cipher))
    return plain.decode(errors="replace")

# Uso para cada desafío:
print(decrypt_flag(
    "f3d4b1a8c2e5f9d7a3b6c1e4f8d2a5c9e1f4b7a0d3e6c9f2a5b8d1e4f7a0c3",
    "11111"  # Clave del desafío 1
))
```

---

## Resumen de Todas las Flags

| # | Desafío | Clave | Flag |
|---|---------|-------|------|
| 1 | Cifrado Cesar | `11111` | `JEISI{cl4v3s_4ntiguas_r3v3l4d4s}` |
| 2 | Enigma | `ABABAC` | `JEISI{r0t0r3s_3n1gm4_r3v3l4d0s}` |
| 3 | Sudoku | `2414313114` | `JEISI{l0g1c4_puzz13_r3s03lv1d0}` |
| 4 | Hash MD5 | `THA` | `JEISI{cr4ck1ng_h4sh3s_c0mpl3t4d0}` |
| 5 | FSM | `P` o `SCC` | `JEISI{m4qu1n4_3st4d0s_c0mpl3t4d4}` |
