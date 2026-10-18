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


def conseguir_nombre_archivo(datos_json):
    return datos_json.get("filename", "desconocido")

def conseguir_version_algoritmo(datos_json):
    return datos_json.get("algorithm_version", "desconocido")

def conseguir_parametros_encripcion(datos_json):
    return datos_json.get("encryption_parameters", "desconocido")


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
        "filename": conseguir_nombre_archivo(datos_json),
        "algorithm_version": conseguir_version_algoritmo(datos_json),
        "encryption_parameters": conseguir_parametros_encripcion(datos_json),
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



