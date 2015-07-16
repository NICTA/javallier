name := "javallier"

version := "0.4.0"

description := "A Java library for Paillier partially homomorphic encryption."

homepage := Some(url("https://github.com/NICTA/javallier"))

organization := "com.n1analytics"

organizationName := "N1 Analytics"

organizationHomepage := Some(url("https://n1analytics.com"))

licenses := Seq("Apache 2.0" -> url("https://www.apache.org/licenses/LICENSE-2.0"))

publishMavenStyle := true

libraryDependencies ++= Seq(
  "ch.qos.logback" % "logback-classic" % "1.0.13",
  "com.novocode" % "junit-interface" % "0.11" % Test
)

publishTo := {
  val nexus = "https://oss.sonatype.org/"
  if (isSnapshot.value)
    Some("snapshots" at nexus + "content/repositories/snapshots")
  else
    Some("releases"  at nexus + "service/local/staging/deploy/maven2")
}

pomExtra := (
  <scm>
    <url>git@github.com:NICTA/javallier.git</url>
    <connection>scm:git:git@github.com:NICTA/javallier.git</connection>
  </scm>
  <developers>
    <developer>
      <id>mpnd</id>
      <name>Mentari Djatmiko</name>
      <url>https://www.nicta.com.au/people/mDjatmiko/</url>
    </developer>
    <developer>
      <id>maxott</id>
      <name>Max Ott</name>
      <url>https://www.nicta.com.au/people/mott/</url>
    </developer>
    <developer>
      <id>hardbyte</id>
      <name>Brian Thorne</name>
      <url>https://www.nicta.com.au/people/bthorne/</url>
    </developer>
  </developers>)

// Solve issue where some loggers are initialised during configuration phase
testOptions in Test += Tests.Setup(classLoader =>
  classLoader
    .loadClass("org.slf4j.LoggerFactory")
    .getMethod("getLogger", classLoader.loadClass("java.lang.String"))
    .invoke(null, "ROOT"))

jacoco.settings
