@Library('ctsrd-jenkins-scripts') _

// Set the default job properties (work around properties() not being additive but replacing)
setDefaultJobProperties([rateLimitBuilds([count: 2, durationName: 'hour', userBoost: true]),
                         [$class: 'GithubProjectProperty', projectUrlStr: 'https://github.com/CTSRD-CHERI/gdb'],
                         copyArtifactPermission('*'),])

cheribuildProject(target: 'gdb',
        targetArchitectures: ["amd64", "aarch64", "mips64", "mips64-purecap", "riscv64", "riscv64-purecap"],
        beforeBuild: 'ls -la $WORKSPACE')


def buildNative(String label) {
    cheribuildProject(target: 'gdb', targetArchitectures: ['native'],
            extraArgs: '--install-prefix=/ --gdb-native/configure-options=--with-python=no',
            tarballName: "gdb-${label}.tar.xz",
            nodeLabel: label,
            sdkCompilerOnly: true,
            uniqueId: "native-${label}",
            beforeBuild: 'ls -la $WORKSPACE')
}

buildNative('linux-latest')
buildNative('linux-baseline')
buildNative('freebsd')
