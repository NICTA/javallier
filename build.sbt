

lazy val commonSettings = Seq(
  homepage := Some(url("https://github.com/NICTA/javallier")),
  organization := "com.n1analytics",
  organizationName := "N1 Analytics",
  organizationHomepage := Some(url("https://n1analytics.com")),
  licenses := Seq("Apache 2.0" -> url("https://www.apache.org/licenses/LICENSE-2.0")),
  publishMavenStyle := true
)



lazy val root = project.in(file(".")).
  settings(commonSettings: _*)
  .settings(
    name := "javallier",
    version := "0.6.0",
    description := "A Java library for Paillier partially homomorphic encryption.",
    libraryDependencies ++= Seq(
      "ch.qos.logback" % "logback-classic" % "1.0.13",
      "commons-cli" % "commons-cli" % "1.3.1",
      "commons-codec" % "commons-codec" % "1.10",
      "com.squareup.jnagmp" % "jnagmp" % "2.0.0",
      "com.fasterxml.jackson.core" % "jackson-databind" % "2.7.0",
      "com.novocode" % "junit-interface" % "0.11" % Test
    ),
    mainClass in Compile := Some("com.n1analytics.paillier.cli.Main")
  ).enablePlugins(JavaAppPackaging)

lazy val benchmark = project.in(file("benchmark")).
  settings(commonSettings: _*).settings(
    name := "javallier-benchmark",
    libraryDependencies ++= Seq(
      "com.squareup.jnagmp" % "jnagmp" % "2.0.0"
      )
  ).dependsOn(root).
  enablePlugins(JmhPlugin)

publishTo := {
  val nexus = "https://oss.sonatype.org/"
  if (isSnapshot.value)
    Some("snapshots" at nexus + "content/repositories/snapshots")
  else
    Some("releases"  at nexus + "service/local/staging/deploy/maven2")
}

pomExtra := (
  <scm>
    <url>git@github.com:n1analytics/javallier.git</url>
    <connection>scm:git:git@github.com:n1analytics/javallier.git</connection>
  </scm>
  <developers>
    <developer>
      <id>mpnd</id>
      <name>Mentari Djatmiko</name>
    </developer>
    <developer>
      <id>maxott</id>
      <name>Max Ott</name>
    </developer>
    <developer>
      <id>hardbyte</id>
      <name>Brian Thorne</name>
    </developer>
    <developer>
      <id>wilko77</id>
      <name>Wilko Henecka</name>
    </developer>
    <developer>
      <id>gusmith</id>
      <name>Guillaume Smith</name>
    </developer>
  </developers>)

// Solve issue where some loggers are initialised during configuration phase
testOptions in Test += Tests.Setup(classLoader =>
  classLoader
    .loadClass("org.slf4j.LoggerFactory")
    .getMethod("getLogger", classLoader.loadClass("java.lang.String"))
    .invoke(null, "ROOT"))

jacoco.settings

assemblyJarName in assembly := "javallier.jar"

test in assembly := {}

mainClass in assembly := Some("com.n1analytics.paillier.cli.Main")

import sbtassembly.AssemblyPlugin.defaultShellScript

assemblyOption in assembly := (assemblyOption in assembly).value.copy(prependShellScript = Some(defaultShellScript))
