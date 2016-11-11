env = Environment()


env.destDir = 'release'
programasDir = env.destDir + '/bin'
env['CCFLAGS'] = ['-ggdb', '-Wall', '-fPIC', '-pipe']

env['LIBPATH'] = []
env['LIBS'] = []

# libcrypto='crypto'
# libcryptoDir = 'linux/lib/' + env.destDir
# hexObj = 'src/hex.o'
# env['CPPPATH'] = []
# env.Object(target = 'src/hex',source = 'src/hex.c')

env['LIBPATH']+=[env.destDir+'/lib']
env['LIBS'] += ['qualipkcs11']


#leToken
leTokenTarget=programasDir+'/leToken'
leTokenSource=['src/leToken.c']
leTokenLibs=[env['LIBS']]
leTokenPDB = []
leTokenIncludes = ['src/include']


leToken = env.Program(
    source =leTokenSource ,
    LIBS =leTokenLibs ,
    PDB =leTokenPDB,
    CPPPATH = leTokenIncludes
)

env.Install(programasDir,leToken)
env.Alias('install',programasDir)