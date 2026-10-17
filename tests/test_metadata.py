import json
import os
from datetime import datetime

def leer_json(ruta_archivo):
    """Abre un archivo JSON y devuelve absolutamente todo, si no existe, da vacío."""
    if not os.path.exists(ruta_archivo):
        return {}
    with open(ruta_archivo, "r", encoding="utf-8") as archivo:
        return json.load(archivo)

def comprobar_contenido(datos_viejos, datos_nuevos):
    """Compara el contenido (no guarda, solo avisa si cambió)."""
    for campo in datos_viejos.keys():
        valor_viejo=datos_viejos.get(campo)
        valor_nuevo=datos_nuevos.get(campo)
        
        if valor_viejo!=valor_nuevo:
            return f"Alerta, el contenido del campo '{campo}' cambio."
            
    return "Contenido intacto."


def comprobar_llaves(datos_viejos, datos_nuevos):
    """Compara las llaves."""
    llaves_viejas=list(datos_viejos.keys())
    llaves_nuevas=list(datos_nuevos.keys())
    
    if llaves_viejas==llaves_nuevas:
        return "Estructura de llaves intacta."
    else:
        return "Alerta, las llaves no concuerdan."


def comprobar_contraseña(datos_json, contraseña_ingresada):
    """Saca la contraseña del JSON y la compara."""
    contraseña_guardada=datos_json.get("contraseña")
    if contraseña_guardada is None:
        return "Error, no hay contraseña en el JSON"
        
    return contraseña_ingresada==contraseña_guardada


def registrar_estado(datos_json, accion, res_contenido, res_llaves, res_password):
    """Recibe los resultados de las comprobaciones anteriores y los guarda."""
    
    historial=datos_json.get("historial", [])
        
    
    nuevo_registro={
        "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "accion": accion,
        "resultado_contenido": res_contenido,
        "resultado_llaves": res_llaves,
        "resultado_password": res_password
    }
    
    
    historial.append(nuevo_registro)
    
    return {"historial": historial}


def guardar_json(estado_nuevo, ruta_archivo="metadata.json"):
    """Guarda en JSON mezclando lo nuevo con lo viejo (sin borrar nada)."""
    
    datos_existentes=leer_json(ruta_archivo)

    if not datos_existentes:
        resultado=estado_nuevo

    else:
        historial_viejo = datos_existentes.get("historial", [])
        historial_nuevo = estado_nuevo.get("historial", [])
        datos_existentes.update(estado_nuevo)
        datos_existentes["historial"] = historial_viejo + historial_nuevo
        resultado=datos_existentes
    
    
    with open(ruta_archivo, "w", encoding="utf-8") as archivo:
        json.dump(resultado, archivo, indent=4)
        
    return "Guardado exitoso (historial actualizado)"



"""

if __name__ == "__main__":
    import os
    
    # Ruta del archivo para las pruebas
    ruta_prueba = "metadata.json"
    
    # Limpiamos el archivo si ya existía de pruebas anteriores
    if os.path.exists(ruta_prueba):
        os.remove(ruta_prueba)
        
    print("=== 🧪 PRUEBA 1: Creando el archivo desde cero ===")
    
    # Datos simulados
    datos_originales = {"nombre": "archivo.txt", "version": 1.0, "contraseña": "123"}
    datos_nuevos = {"nombre": "archivo.txt", "version": 1.0, "contraseña": "123"}
    
    # Comprobamos (todo debería estar bien)
    res_contenido = comprobar_contenido(datos_originales, datos_nuevos)
    res_llaves = comprobar_llaves(datos_originales, datos_nuevos)
    res_password = comprobar_contraseña(datos_nuevos, "123")
    
    # Registramos y guardamos
    estado_nuevo = registrar_estado(datos_nuevos, "cifrar_archivo", res_contenido, res_llaves, res_password)
    print(guardar_json(estado_nuevo, ruta_prueba))
    print("Contenido actual en el JSON:", leer_json(ruta_prueba))
    
    
    print("\n=== 🧪 PRUEBA 2: Añadiendo otro registro (sin borrar el anterior) ===")
    
    # Simulamos que un hacker modificó el nombre del archivo
    datos_hackeados = {"nombre": "virus.exe", "version": 1.0, "contraseña": "123"}
    
    # Comprobamos (el contenido debería marcar alerta)
    res_contenido_hack = comprobar_contenido(datos_originales, datos_hackeados)
    res_llaves_hack = comprobar_llaves(datos_originales, datos_hackeados)
    res_password_hack = comprobar_contraseña(datos_hackeados, "123")
    
    # Registramos y guardamos de nuevo
    estado_hackeado = registrar_estado(datos_hackeados, "descifrar_archivo", res_contenido_hack, res_llaves_hack, res_password_hack)
    print(guardar_json(estado_hackeado, ruta_prueba))
    
    print("\n¡Revisa tu explorador de archivos! Se debe haber creado 'metadata.json'")
    print("Contenido final del JSON (nota cómo el historial tiene 2 registros):")
    print(json.dumps(leer_json(ruta_prueba), indent=4))
    """