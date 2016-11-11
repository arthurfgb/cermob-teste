env = Environment()


env.destDir = 'release'
programasDir = env.destDir + '/bin'
env['CCFLAGS'] = ['-ggdb', '-Wall', '-fPIC', '-pipe']
env['CPPPATH'] = ['src/include']
env['LIBPATH']=['lib']
env['LIBS'] = ['qualipkcs11', 'crypto']
env['LD_LIBRARY_PATH']=['lib']

#assinaLib
assinaLibTarget='lib/libassina'
assinaLibSource=['src/assinaLib.c']

assinaLib=env.SharedLibrary(
            target = assinaLibTarget,
	source = assinaLibSource
)

#leToken
# leTokenTarget=programasDir+'/leToken'
# leTokenSource=['src/leToken.c']
# leTokenLibs=[env['LIBS']]
# leTokenPDB = []
# leTokenIncludes = ['src/include']


# leToken = env.Program(
#     source =leTokenSource ,
#     LIBS =leTokenLibs ,
#     PDB =leTokenPDB,
#     CPPPATH = leTokenIncludes
# )


#aplicacaoAssina
aplicacaoAssinaTarget= programasDir+'/aplicacaoAssina'
aplicacaoAssinaSource=['src/aplicacaoAssina.c']
aplicacaoAssinaLibs=['libassina']
aplicacaoAssinaLibpath=['lib']

aplicacaoAssina=env.Program(
    target = aplicacaoAssinaTarget,
    source = aplicacaoAssinaSource,
    LIBS = aplicacaoAssinaLibs,
    LIBPATH = aplicacaoAssinaLibpath

)

# env.Install(aplicacaoAssinaTarget,aplicacaoAssina)
# env.Alias('install',aplicacaoAssinaTarget)