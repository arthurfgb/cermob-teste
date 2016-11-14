import os;
Import('*')

src = 'src'
programasDir = '../' + env.destDir + '/bin'

hexSource = src + '/hex.c'
getoptSource = src + '/getopt_win32.c'
getoptObj = src + '/getopt_win32.obj'

env['LIBPATH'] = []
env['LIBS'] = []

if env['PLATFORM'] == 'win32':
	libcrypto = 'libeay32'
	libcryptoDir = 'win32/lib/' + env.destDir
	hexObj = src + '/hex.obj'
	env.Object(target = src + '/getopt_win32', source = getoptSource)
	env['CPPDEFINES'] = [('WIN32', 1), ('_CRT_SECURE_NO_DEPRECATE', 1)]
	env['CPPPATH'] = ['src/win32/include']
	env['LIBPATH'] = ['src/win32/lib']
	env['LIBS'] = ['user32.lib', 'Advapi32.lib', 'gdi32.lib']

else:
	libcrypto = 'crypto'
	libcryptoDir = 'linux/lib/' + env.destDir
	hexObj = src + '/hex.o'
	env['CPPPATH'] = []
env.Object(
	target =  src + '/hex',
	source = hexSource
)

env['CPPPATH'] += ['src', '../src/include']
env['LIBPATH'] += ['../' + env.destDir + '/lib', libcryptoDir]
env['LIBS'] += ['qualipkcs11']
env['PDB'] = []

#geraChaves
geraChavesTarget = programasDir + '/geraChaves'
geraChavesSource = [src + '/geraChaves.c', hexObj]
geraChavesLibs = [env['LIBS'], [libcrypto]]
geraChavesPDB = [];
if env['PLATFORM'] == 'win32':
	geraChavesSource += [getoptObj]
if env.debug == '1':
	geraChavesPDB = geraChavesTarget + '.pdb'

env.Program(
	target = geraChavesTarget,
	source = geraChavesSource,
	LIBS = geraChavesLibs,
	PDB = geraChavesPDB
)

#importaChaves
importaChavesTarget = programasDir + '/importaChaves'
importaChavesSource = [src + '/importaChaves.c', hexObj]
importaChavesLibs = [env['LIBS'], libcrypto]
importaChavesPDB = []
if env['PLATFORM'] == 'win32':
	importaChavesSource += [getoptObj]
	importaChavesLibs += ['User32.lib', 'Gdi32.lib', 'Advapi32.lib']
if env.debug == '1':
	importaChavesPDB = importaChavesTarget + '.pdb'

env.Program(
	target = importaChavesTarget,
	source = importaChavesSource,
	LIBS = importaChavesLibs,
	PDB = importaChavesPDB
)

#mechTypes
mechTypesTarget = programasDir + '/mechTypes'
mechTypesSource = [src + '/mechTypes.c']
mechTypesPDB = []
if env['PLATFORM'] == 'win32':
	mechTypesSource += [getoptObj]
if env.debug == '1':
	mechTypesPDB = mechTypesTarget + '.pdb'

env.Program(
	target = mechTypesTarget,
	source = mechTypesSource,
	PDB = mechTypesPDB
)

#pegaIdCert
pegaIdCertTarget = programasDir + '/pegaIdCert'
pegaIdCertSource = [src + '/pegaIdCert.c', hexObj]
pegaIdCertPDB = []
if env['PLATFORM'] == 'win32':
	pegaIdCertSource += [getoptObj]
if env.debug == '1':
	pegaIdCertPDB = pegaIdCertTarget + '.pdb'

env.Program(
	target = pegaIdCertTarget, 
	source = pegaIdCertSource,
	PDB = pegaIdCertPDB
)

#pegaLabelSerial
pegaLabelSerialTarget = programasDir + '/pegaLabelSerial'
pegaLabelSerialSource = [src + '/pegaLabelSerial.c']
pegaLabelSerialPDB = []
if env['PLATFORM'] == 'win32':
	pegaLabelSerialSource += [getoptObj]
if env.debug == '1':
	pegaLabelSerialPDB = pegaLabelSerialTarget + '.pdb'

env.Program(
	target = pegaLabelSerialTarget, 
	source = pegaLabelSerialSource,
	PDB = pegaLabelSerialPDB
)

#verificaPin
verificaPinTarget = programasDir + '/verificaPin'
verificaPinSource = [src + '/verificaPin.c']
verificaPinPDB = []
if env['PLATFORM'] == 'win32':
	verificaPinSource += [getoptObj]
if env.debug == '1':
	verificaPinPDB = verificaPinTarget + '.pdb'

env.Program(
	target = verificaPinTarget,
	source = verificaPinSource,
	PDB = verificaPinPDB
)

#pegaCert
pegaCertTarget = programasDir + '/pegaCert'
pegaCertSource = [src + '/pegaCert.c']
pegaCertPDB = []
if env['PLATFORM'] == 'win32':
	pegaCertSource += [getoptObj]
if env.debug == '1':
	pegaCertPDB = pegaCertTarget + '.pdb'

env.Program(
	target = pegaCertTarget, 
	source = pegaCertSource,
	PDB = pegaCertPDB
)

#pegaIdChave
pegaIdChaveTarget = programasDir + '/pegaIdChave'
pegaIdChaveSource = [src + '/pegaIdChave.c', hexObj]
pegaIdChavePDB = []
if env['PLATFORM'] == 'win32':
	pegaIdChaveSource += [getoptObj]
if env.debug == '1':
	pegaIdChavePDB = pegaIdChaveTarget + '.pdb'

env.Program(
	target = pegaIdChaveTarget, 
	source = pegaIdChaveSource,
	PDB = pegaIdChavePDB
)

#zeraCartao
zeraCartaoTarget = programasDir + '/zeraCartao'
zeraCartaoSource = [src + '/zeraCartao.c']
zeraCartaoPDB = []
if env['PLATFORM'] == 'win32':
	zeraCartaoSource += [getoptObj]
if env.debug == '1':
	zeraCartaoPDB = zeraCartaoTarget + '.pdb'

env.Program(
	target = zeraCartaoTarget,
	source = zeraCartaoSource,
	PDB = zeraCartaoPDB
)

#tokenInfo
tokenInfoTarget = programasDir + '/tokenInfo'
tokenInfoSource = [src + '/tokenInfo.c']
tokenInfoPDB = []
if env.debug == '1':
	tokenInfoPDB = tokenInfoTarget + '.pdb'

env.Program(
	target = tokenInfoTarget,
	source = tokenInfoSource,
	PDB = tokenInfoPDB
)

#leObjetos
leObjetosTarget = programasDir + '/leObjetos'
leObjetosSource = [src + '/leObjetos.c']
leObjetosLibs = [env['LIBS'], libcrypto]
leObjetosPDB = []
if env['PLATFORM'] == 'win32':
	leObjetosSource += [getoptObj]
	leObjetosLibs += ['User32.lib', 'Gdi32.lib', 'Advapi32.lib']
if env.debug == '1':
	leObjetosPDB = leObjetosTarget + '.pdb'

env.Program(
	target = leObjetosTarget, 
	source = leObjetosSource, 
	LIBS = leObjetosLibs,
	PDB = leObjetosPDB
)

#limpaCartao
limpaCartaoTarget = programasDir + '/limpaCartao'
limpaCartaoSource = [src + '/limpaCartao.c']
limpaCartaoPDB = []
if env['PLATFORM'] == 'win32':
	limpaCartaoSource += [getoptObj]
if env.debug == '1':
	limpaCartaoPDB = limpaCartaoTarget + '.pdb'

env.Program(
	target = limpaCartaoTarget, 
	source = limpaCartaoSource,
	PDB = limpaCartaoPDB
)

#testaTentativas
testaTentativasTarget = programasDir + '/testaTentativas'
testaTentativasSource = [src + '/testaTentativas.c']
testaTentativasPDB = []
if env['PLATFORM'] == 'win32':
	testaTentativasSource += [getoptObj]
if env.debug == '1':
	testaTentativasPDB = testaTentativasTarget + '.pdb'

env.Program(
	target = testaTentativasTarget, 
	source = testaTentativasSource,
	PDB = testaTentativasPDB
)

# criptograga
criptografaTarget = programasDir + '/criptografa'
criptografaSource = [src + '/criptografa.c', hexObj]
criptografaPDB = []
if env['PLATFORM'] == 'win32':
	criptografaSource += [getoptObj]
if env.debug == '1':
	criptografaPDB = criptografaTarget + '.pdb'

env.Program(
	target = criptografaTarget, 
	source = criptografaSource,
	CPPDEFINES = env['CPPDEFINES'] + [('DECRYPT', 0)],
	PDB = criptografaPDB
)

# descriptografa
descriptografaTarget = programasDir + '/descriptografa'
descriptografaSource = [src + '/descriptografa.c', hexObj]
descriptografaPDB = []
if env['PLATFORM'] == 'win32':
	descriptografaSource += [getoptObj]
if env.debug == '1':
	descriptografaPDB = descriptografaTarget + '.pdb'

env.Program(
	target = descriptografaTarget,
	source = descriptografaSource,
	CPPDEFINES = env['CPPDEFINES'] + [('DECRYPT', 1)],
	PDB = descriptografaPDB
)

#setAttrib
#setAttribTarget = programasDir + '/setAttrib'
#setAttribSource = [src + '/setAttrib.c']
#setAttribPDB = []
#if env['PLATFORM'] == 'win32':
#	setAttribSource += [getoptObj]
#if env.debug == '1':
#	setAttribPDB = setAttribTarget + '.pdb'
#
#env.Program(
#	target = setAttribTarget, 
#	source = setAttribSource,
#	PDB = setAttribPDB
#)

#leValores
leValoresTarget = programasDir + '/leValores'
leValoresSource = [src + '/leValores.c']
leValoresPDB = []
if env['PLATFORM'] == 'win32':
	leValoresSource += [getoptObj]
if env.debug == '1':
	leValoresPDB = leValoresTarget + '.pdb'

env.Program(
	target = leValoresTarget, 
	source = leValoresSource,
	PDB = leValoresPDB
)

#trocaPin
trocaPinTarget = programasDir + '/trocaPin'
trocaPinSource = [src + '/trocaPin.c']
trocaPinPDB = []
if env['PLATFORM'] == 'win32':
	trocaPinSource += [getoptObj]
if env.debug == '1':
	trocaPinPDB = trocaPinTarget + '.pdb'

env.Program(
	target = trocaPinTarget, 
	source = trocaPinSource,
	PDB = trocaPinPDB
)

#testaPkcs11
testaPkcs11Target = programasDir + '/testaPkcs11'
testaPkcs11Source = [src + '/testaPkcs11.c']
testaPkcs11PDB = []
if env['PLATFORM'] == 'win32':
	testaPkcs11Source += [getoptObj]
if env.debug == '1':
	testaPkcs11PDB = testaPkcs11Target + '.pdb'

env.Program(
	target = testaPkcs11Target, 
	source = testaPkcs11Source,
	PDB = testaPkcs11PDB
)

#infoCard
infoCardTarget = programasDir + '/infoCard'
infoCardSource = [src + '/infoCard.c']
infoCardPDB = []
if env.debug == '1':
	infoCardPDB = infoCardTarget + '.pdb'

env.Program(
	target = infoCardTarget,
	source = infoCardSource,
	PDB = infoCardPDB
)

#gravaCertificado
gravaCertificadoTarget = programasDir + '/gravaCertificado'
gravaCertificadoSource = [src + '/gravaCertificado.c', hexObj]
gravaCertificadoLibs = [env['LIBS'], [libcrypto]]
gravaCertificadoPDB = []
if env['PLATFORM'] == 'win32':
	gravaCertificadoSource += [getoptObj]
	gravaCertificadoLibs += ['User32.lib', 'Gdi32.lib', 'Advapi32.lib']
if env.debug == '1':
	gravaCertificadoPDB = gravaCertificadoTarget + '.pdb'

env.Program(
	target = gravaCertificadoTarget,
	source = gravaCertificadoSource,
	LIBS = gravaCertificadoLibs,
	PDB = gravaCertificadoPDB
)

#unlockPin
unlockPinTarget = programasDir + '/unlockPin'
unlockPinSource = [src + '/unlockPin.c', hexObj]
unlockPinLibs = [env['LIBS'], [libcrypto]]
unlockPinPDB = []
if env['PLATFORM'] == 'win32':
	unlockPinSource += [getoptObj]
	unlockPinLibs += ['User32.lib', 'Gdi32.lib', 'Advapi32.lib']
if env.debug == '1':
	unlockPinPDB = unlockPinTarget + '.pdb'

env.Program(
	target = unlockPinTarget,
	source = unlockPinSource,
	LIBS = unlockPinLibs,
	PDB = unlockPinPDB
)

#trocaPuk
trocaPukTarget = programasDir + '/trocaPuk'
trocaPukSource = [src + '/trocaPuk.c', hexObj]
trocaPukLibs = [env['LIBS'], [libcrypto]]
trocaPukPDB = []
if env['PLATFORM'] == 'win32':
	trocaPukSource += [getoptObj]
	trocaPukLibs += ['User32.lib', 'Gdi32.lib', 'Advapi32.lib']
if env.debug == '1':
	trocaPukPDB = trocaPukTarget + '.pdb'

env.Program(
	target = trocaPukTarget,
	source = trocaPukSource,
	LIBS = trocaPukLibs,
	PDB = trocaPukPDB
)

#reset
resetTarget = programasDir + '/reset'
resetSource = [src + '/reset.c', hexObj]
resetLibs = [env['LIBS'], [libcrypto]]
resetPDB = []
if env['PLATFORM'] == 'win32':
	resetSource += [getoptObj]
	resetLibs += ['User32.lib', 'Gdi32.lib', 'Advapi32.lib']
if env.debug == '1':
	resetPDB = resetTarget + '.pdb'

env.Program(
	target = resetTarget,
	source = resetSource,
	LIBS = resetLibs,
	PDB = resetPDB
)

# testaInitPIN
testaInitPINTarget = programasDir + '/testaInitPIN'
testaInitPINSource = [src + '/testaInitPIN.c', hexObj]
testaInitPINLibs = [env['LIBS'], [libcrypto]]
testaInitPINPDB = []
if env['PLATFORM'] == 'win32':
	testaInitPINSource += [getoptObj]
	testaInitPINLibs += ['User32.lib', 'Gdi32.lib', 'Advapi32.lib']
if env.debug == '1':
	testaInitPINPDB = testaInitPINTarget + '.pdb'

env.Program(
	target = testaInitPINTarget,
	source = testaInitPINSource,
	LIBS = testaInitPINLibs,
	PDB = testaInitPINPDB
)

# testaInitPINPUK
testaInitPINPUKTarget = programasDir + '/testaInitPINPUK'
testaInitPINPUKSource = [src + '/testaInitPINPUK.c', hexObj]
testaInitPINPUKLibs = [env['LIBS'], [libcrypto]]
testaInitPINPUKPDB = []
if env['PLATFORM'] == 'win32':
	testaInitPINPUKSource += [getoptObj]
	testaInitPINPUKLibs += ['User32.lib', 'Gdi32.lib', 'Advapi32.lib']
if env.debug == '1':
	testaInitPINPUKPDB = testaInitPINPUKTarget + '.pdb'

env.Program(
	target = testaInitPINPUKTarget,
	source = testaInitPINPUKSource,
	LIBS = testaInitPINPUKLibs,
	PDB = testaInitPINPUKPDB
)

# leVersao
leVersaoTarget = programasDir + '/leVersao'
leVersaoSource = [src + '/leVersao.cpp']
leVersaoLibs = [env['LIBS']]
leVersaoPDB = []
if env['PLATFORM'] == 'win32':
	leVersaoLibs += ['User32.lib', 'Gdi32.lib', 'Advapi32.lib']
	if env.debug == '1':
		leVersaoPDB = leVersaoTarget + '.pdb'

env.Program(
	target = leVersaoTarget,
	source = leVersaoSource,
	LIBS = leVersaoLibs,
	PDB = leVersaoPDB
)

# assina
assinaTarget = programasDir + '/assina'
assinaSource = src + '/assina.c'
assinaLibs = [env['LIBS'], libcrypto]
assinaPDB = []
if env['PLATFORM'] == 'win32':
	assinaSource += getoptObj
	assinaLibs += ['User32.lib', 'Gdi32.lib', 'Advapi32.lib']

env.Program(
	target = assinaTarget,
	source = assinaSource,
	CPPDEFINES = env['CPPDEFINES'] + [('ASSINA_SINGLE_PART', 1), ('ASSINA_MULT_PART', 0)],
	LIBS = assinaLibs,
	PDB = assinaTarget + '.pdb'
)
