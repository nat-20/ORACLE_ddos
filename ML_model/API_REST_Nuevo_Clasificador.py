from bottle import Bottle, run, request
import json
import numpy as np
#from sklearn.externals import joblib
import joblib
import time
import csv
from sklearn.metrics import confusion_matrix
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score

app = Bottle()
aciertosT = 0;
total = 0;
TotReq = 0;
cont_A = 0;
cont_B = 0;
cont_AD = 0;
cont_BD = 0;
@app.route('/clasificar', method='POST')
def alarma():
	global clf
	global normalizador
	global aciertosT
	global total
	global TotReq
	global cont_A
	global cont_B
	global cont_AD
	global cont_BD

	T_ini = int(round(time.time() * 1000)) # TimeStamp inicial en milisegundos
	r = json.load(request.body) # se extrae el body de la peticion POST
	#print("prueba: ", r, len(r))
	r = np.asarray(r, dtype=np.float64)
	#print('rrrrrrrrrrrrrrrrr: \n', r)
	L = r.shape

	#tiempos[0,0] -> timestamp ; tiempos[0,1] -> TimeSpentONOS
	tiempos = r[L[0]-1,:]
	print("tiempos:", tiempos.shape)

	#--- se extrae toda la matriz menos la ultima fila y columna
	features = r[0:L[0]-1,0:L[1]-1]
	#print("features: ",features)

	#--- se extrae la ultima columna sin el ultimo valor.
	tags = np.array(r[0:L[0]-1,L[1]-1].T,dtype=int)
	#tags = np.array(r[0:L[0]-1,L[1]-1])
	print("tags:",tags)
	print("=========================================")
	scaler = StandardScaler()
	features_N = scaler.fit_transform(features)

	#features_N = estandarizador.transform(features)
	y = clf.predict(features_N) # clasificador
	yNew = y.copy()
	#for i in range(len(y)):
	#	if y[i] == 'BENIGN':
	#		yNew[i] = 0
	#	else:
	#		yNew[i] = 1
	tagsNew = y.copy()
	
	#for i in range(len(tags)):
        #        if tags[i] == 0:
        #                tagsNew[i] = 'BENIGN'
        #        else:
        #                tagsNew[i] = 'PortScan'

	T_fin = int(round(time.time() * 1000)) # TimeStamp final en milisegundos
	print("Time spent Classifier: ",T_fin - T_ini)

	trues = 0
	tam = len(y)
	for i in range(0,tam):
		if y[i] == tags[i]:
			trues += 1
		if y[i] == 1:
			cont_AD += 1
		elif y[i] == 0:
			cont_BD += 1
		if tags[i] == 1:
			cont_A += 1
		elif tags[i] == 0:
			cont_B += 1

	#print("yNew: ", yNew)
	
	# se adicional a los aciertos totales	
	aciertosT += trues
	total += tam 

	print("Classificación:",y)
	print("Reales: ", tags)
	print("==================================================")
	print("aciertos: ", aciertosT, "desaciertos: ",total - aciertosT, "accuracy: ",aciertosT/total)
	print("--------------------------------------------------")
	print("Benignos Verdaderos: ",cont_B)
	print("Benignos detectados: ",cont_BD)
	print("Ataques Verdaderos: ",cont_A)
	print("Ataques detectados: ",cont_AD)
	print("--------------------------------------------------")
	matrix = confusion_matrix(tagsNew,y)
	print("Matriz de Confusión: \n", matrix)
	#print('f1 score: %.5f' % f1_score(tagsNew, y,average="binary", pos_label='PortScan'))
	data = [TotReq, tiempos[1], T_fin - T_ini, T_fin - tiempos[0], tiempos[2]]
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
	#estandarizador = joblib.load('RF_StandSet1_W40_Impar.joblib')
	#print(estandarizador) 

	#cargar el modelo de machine learning
	#clf = joblib.load('KNN_modelSet1_W60_Impar.joblib') # del modelo RF
	#clf = joblib.load('model_RF_60.joblib')
	clf = joblib.load('Models/model_KNN_60_2.joblib')
	print("-------------------- Modelo ML -------------------")
	print(clf)
	print("--------------------------------------------------")
	#------------------------------------------------------------------------------

	run() #arranca el servicio API-REST
