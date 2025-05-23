name := "rtl-fuzz-lab"
version := "0.1"
scalaVersion := "2.12.13"
crossScalaVersions := Seq("2.12.13", "2.13.5")

scalacOptions ++= Seq(
  "-language:reflectiveCalls",
  "-deprecation",
  "-feature",
  "-Xcheckinit"
) ++ {
  CrossVersion.partialVersion(scalaVersion.value) match {
    case Some((2, n)) if n >= 13 => Seq("-Ymacro-annotations")
    case _                       => Nil
  }
}

// SNAPSHOT repositories
resolvers += Resolver.sonatypeRepo("snapshots")

// libraryDependencies += "edu.berkeley.cs" %% "chiseltest" % "0.5-SNAPSHOT"
// libraryDependencies += "edu.berkeley.cs" % "chiseltest_2.13" % "6.0-SNAPSHOT"
libraryDependencies += "edu.berkeley.cs" %% "chiseltest" % "8.8.8"
libraryDependencies += "org.scalatest" %% "scalatest" % "3.2.6" % Test
//libraryDependencies += "com.lihaoyi" %% "upickle" % "1.4.2"
libraryDependencies += "com.google.guava" % "guava" % "30.1-jre"
libraryDependencies += "net.openhft" % "affinity" % "3.0.2"

scalaSource in Compile := baseDirectory.value / "src"
scalaSource in Test := baseDirectory.value / "test"
resourceDirectory in Test := baseDirectory.value / "test" / "resources"

libraryDependencies += "org.eclipse.collections" % "eclipse-collections" % "11.1.0"
