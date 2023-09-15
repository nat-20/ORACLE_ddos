from bottle import Bottle, run, request
import json
import numpy as np
#from sklearn.externals import joblib
import joblib
import time
import csv


app = Bottle()
aciertosT = 0;
total = 0;
TotReq = 0;

@app.route('/clasificar', method='POST')
def alarma():
	global clf
	global normalizador
	global aciertosT
	global total
	global TotReq

	T_ini = int(round(time.time() * 1000)) # TimeStamp inicial en milisegundos
	r = json.load(request.body) # se extrae el body de la peticion POST
	#print("prueba: ", r, len(r))
	r = np.matrix(r, dtype=np.float64)
	L = r.shape

	#tiempos[0,0] -> timestamp ; tiempos[0,1] -> TimeSpentONOS
	tiempos = r[L[0]-1,:]
	#print("tiempos:", tiempos)

	#--- se extrae toda la matriz menos la ultima fila y columna
	features = r[0:L[0]-1,0:L[1]-1]
	#print("features: ",features)

	#--- se extrae la ultima columna sin el ultimo valor.
	tags = np.array(r[0:L[0]-1,L[1]-1].T,dtype=int)
	#print("tags:",tags)

	features_N = estandarizador.transform(features)
	y = clf.predict(features_N) # clasificador

	T_fin = int(round(time.time() * 1000)) # TimeStamp final en milisegundos
	print("Time spent Classifier: ",T_fin - T_ini)

	trues = 0
	tam = len(y)
	for i in range(0,tam):
		if y[i] == tags[0,i]:
			trues += 1

	# se adicional a los aciertos totales	
	aciertosT += trues
	total += tam 

	print("Classificación:",y)
	print("Reales: ", tags)
	print("aciertos: ", aciertosT, "desaciertos: ",total - aciertosT, "accuracy: ",aciertosT/total)
	print("--------------------------------------------------")

	data = [TotReq, tiempos[0,1], T_fin - T_ini, T_fin - tiempos[0,0], tiempos[0,2]]
	archivo = open("times.csv","a",)
	salida = csv.writer(archivo)
	salida.writerow(data)
	del salida
	archivo.close()

	TotReq += 1


def run():
    try:
        app.run(host='0.0.0.0', port=5000)
    except:
        print("An exception occurred")



if __name__ == "__main__":

	#--------------- Crea o sobreescribe el archivo -----------------------
	archivo = open("times.csv","w")
	salida = csv.writer(archivo)
	salida.writerow(['#', 'TimeSpentONOS', 'TimeSpentClassif', 'TimeSpentTot','FlowPerPkt'])
	del salida
	archivo.close()

	#------------------------ Initializar modelo ML --------------------------------
	# cargar la matriz con las medias y desviacion estandar del conjunto de entrenamiento
	
	#estandarizador = joblib.load('KNN_StandSet1_W60_Impar.joblib')
	estandarizador = joblib.load('RF_StandSet1_W40_Impar.joblib')
	print(estandarizador) 

	#cargar el modelo de machine learning
	#clf = joblib.load('KNN_modelSet1_W60_Impar.joblib') # del modelo RF
	clf = joblib.load('RF_modelSet1_W40_Impar.joblib')
	print("-------------------- Modelo ML -------------------")
	print(clf)
	print("--------------------------------------------------")
	#------------------------------------------------------------------------------

	run() #arranca el servicio API-REST
