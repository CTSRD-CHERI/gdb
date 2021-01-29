@Library('ctsrd-jenkins-scripts') _

// Set the default job properties (work around properties() not being additive but replacing)
setDefaultJobProperties([rateLimitBuilds([count: 2, durationName: 'hour', userBoost: true]),
                         [$class: 'GithubProjectProperty', projectUrlStr: 'https://github.com/CTSRD-CHERI/gdb'],
                         copyArtifactPermission('*'),])

def buildNative(String label) {
    cheribuildProject(target: 'gdb', targetArchitectures: ['native'],
            extraArgs: '--install-prefix=/ --gdb-native/configure-options=--with-python=no',
            tarballName: "gdb-${label}.tar.xz",
            nodeLabel: label,
            sdkCompilerOnly: true,
            uniqueId: "native-${label}",
            stageSuffix: label
            beforeBuild: 'ls -la $WORKSPACE')
}

parallel(['linux-latest'  : { buildNative('linux-latest') },
          'linux-baseline': { buildNative('linux-baseline') },
          'freebsd'       : { buildNative('freebsd') }])

cheribuildProject(target: 'gdb',
        targetArchitectures: ["amd64", "aarch64", "mips64", "mips64-hybrid", "riscv64", "riscv64-hybrid"],
        beforeBuild: 'ls -la $WORKSPACE')
