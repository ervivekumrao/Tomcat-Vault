# Encrypt Tomcat Connection Pool

## Features

- Supports both `Tomcat DBCP2 Connection Pool` and `Tomcat JDBC Connection Pool` datasource attribute encryption.
- This project support almost all `Tomcat database resource attribute value` encryption and decryption except `factory` attribute. Due to the fact that `factory` is needed for identification of encryption handling class.
- It is advised to use encryption for database username, password and JDBC URL or password only.
- You can even modify your encryption key and algorithms for custom encryption jar. Read `Change Encryption Algorithm and Key` section for
   details. For this requirement you need to build custom jar.

## How to use this Project in your Tomcat

- To encrypt database username, password and JDBC URL use `tomcat-cp-encryption.jar` file from project `Releases`.
- Encrypt original username, password and JDBC URL attribute values.
- Replace encrypted values in your resource configuration as shown in `Choose Factory Based On Connection Pool Type` section.
- Copy `tomcat-cp-encryption.jar` jar into tomcat's `apache-tomcat-9.0.96/lib/` directory.
- At run time `tomcat-cp-encryption.jar` will automatically identify which attribute is encrypted and try to decrypt only those.
- Restart your Tomcat server.

## How To Build JAR
- Download this project.
- Extract project zip files.
- Make sure extracted project directory name is `EncryptTomcatConnectionPool` not something like `EncryptTomcatConnectionPool-master`.
- Open this as project with `IntelliJ Idea`
- Copy latest `tomcat-dbcp.jar` and `tomcat-jdbc.jar` from Tomcat server `apache-tomcat-9.0.96/lib/` to project `libs` directory.
- Or download from `Maven` artifactory  
   >https://mvnrepository.com/artifact/org.apache.tomcat/tomcat-jdbc  
   https://mvnrepository.com/artifact/org.apache.tomcat/tomcat-dbcp
- Refresh project so libs show up in the structure (right click on project top level, refresh/synchronize)
- Expand libs and right-click on the jar > add as Library...
- This project is built on Java 8.
-  Navigate to `File` > `Project Structure` > `Artifacts` > Under Artifacts click `+` > `JAR` > `From modules with dependency`
-  Provide name to build. Same way you can also modify jar name.
-  Make sure you have included `'EncryptTomcatConnectionPool' compile output` from right side `Available Elements` to left under jar name.
-  You may need to include `umrao.encrypt.EncryptDecrypt` class as main class.
-  Now you are ready for build `Build` > `Build artifacts...` > On the popup menu under `Build Artifacts` select the build name you gave in step 2 > under `Action` select `Build`.
-  You can find your jar under `out/artifacts/` directory.

## How To Use Encryption/Decryption

Encrypt/decrypt username, password and URL with below command. Use `-e` for encryption and `-d` for decryption.

    $ java -jar  tomcat-cp-encryption.jar -e/-d MSG_TO_ENCRYPT_DECRYPT

or

    $ java -cp tomcat-cp-encryption.jar umrao.encrypt.EncryptDecrypt -e/-d MSG_TO_ENCRYPT_DECRYPT

encrypt or decrypt username, password and JDBC URL one by one
example:

To encrypt `username="DB_USERNAME"`

    $ java -jar tomcat-cp-encryption.jar -e DB_USERNAME

To encrypt `password="DB_PASSWORD"`

    $ java -jar tomcat-cp-encryption.jar -e DB_PASSWORD

To encrypt `url="DB_JDBC_URL"`

    $ java -jar tomcat-cp-encryption.jar -e DB_JDBC_URL

This will generate encrypted string that can be used in resource
Or Run umrao/encrypt/EncryptDecrypt.java from IntelliJ with your input values by modifying it.

## Choose Factory Based On Connection Pool Type

In `context.xml` or `server.xml` resource attributes; add factory according to your connection pool type

#### Tomcat JDBC Connection Pool

    factory="org.apache.tomcat.jdbc.pool.EncryptDataSourceFactory"

>Please refer tomcat official document for detailed list of `Tomcat JDBC Connection Pool` attributes.  
>https://tomcat.apache.org/tomcat-9.0-doc/jdbc-pool.html

###### Sample resource configuration: Before encryption

    <Resource name="jdbc/MSSQLDB"
              auth="Container"
              type="javax.sql.DataSource"
              fairQueue="true"
              singleton="true"
              driverClassName="com.microsoft.sqlserver.jdbc.SQLServerDriver"
              factory="org.apache.tomcat.jdbc.pool.EncryptDataSourceFactory"
              url="jdbc:sqlserver://localhost:1433;databaseName=mssqldb;SelectMethod=cursor;SendStringParametersAsUnicode=false;trustServerCertificate=true"
              username="mssqlUser"
              password="mssqlPassword"
              maxActive="100"
              maxIdle="30"
              maxWait="10000"
              initialSize="1"/>

###### Generate encrypted values.

    $ java -jar tomcat-cp-encryption.jar -e "jdbc:sqlserver://localhost:1433;databaseName=mssqldb;SelectMethod=cursor;SendStringParametersAsUnicode=false;trustServerCertificate=true"
    encrypted: 386C335A784C2F682F77324C55414C3543576F51355536714E636B746E764639736B5A3757632F69715876643531583173586B444174454D49714D7A644E4279796D3259422F644C356F73536E58795333426D55656D5735507869597845694A75326D4D686F58384D5441346E36546D57326C316632727676543348625757535151466D747075576C667442727A556346393442685537464E6355786A62727553674F5131533766514531714E583237696863684D654A45515358316831765440232324242426262626
    $ java -jar tomcat-cp-encryption.jar -d "386C335A784C2F682F77324C55414C3543576F51355536714E636B746E764639736B5A3757632F69715876643531583173586B444174454D49714D7A644E4279796D3259422F644C356F73536E58795333426D55656D5735507869597845694A75326D4D686F58384D5441346E36546D57326C316632727676543348625757535151466D747075576C667442727A556346393442685537464E6355786A62727553674F5131533766514531714E583237696863684D654A45515358316831765440232324242426262626"
    decrypted: jdbc:sqlserver://localhost:1433;databaseName=mssqldb;SelectMethod=cursor;SendStringParametersAsUnicode=false;trustServerCertificate=true
    $ java -jar tomcat-cp-encryption.jar -e "mssqlUser"
    encrypted: 5837476D517479624B5335383446514F444D764B57413D3D40232324242426262626
    $ java -jar tomcat-cp-encryption.jar -d "5837476D517479624B5335383446514F444D764B57413D3D40232324242426262626"
    decrypted: mssqlUser
    $ java -jar tomcat-cp-encryption.jar -e "mssqlPassword"
    encrypted: 71672F2B566E496D796E6168734D5977543378626A673D3D40232324242426262626
    $ java -jar tomcat-cp-encryption.jar -d "71672F2B566E496D796E6168734D5977543378626A673D3D40232324242426262626"
    decrypted: mssqlPassword

###### Sample resource configuration after replacing with encrypted values

    <Resource name="jdbc/MSSQLDB"
              auth="Container"
              type="javax.sql.DataSource"
              fairQueue="true"
              singleton="true"
              driverClassName="com.microsoft.sqlserver.jdbc.SQLServerDriver"
              factory="org.apache.tomcat.jdbc.pool.EncryptDataSourceFactory"
              url="386C335A784C2F682F77324C55414C3543576F51355536714E636B746E764639736B5A3757632F69715876643531583173586B444174454D49714D7A644E4279796D3259422F644C356F73536E58795333426D55656D5735507869597845694A75326D4D686F58384D5441346E36546D57326C316632727676543348625757535151466D747075576C667442727A556346393442685537464E6355786A62727553674F5131533766514531714E583237696863684D654A45515358316831765440232324242426262626"          
              username="5837476D517479624B5335383446514F444D764B57413D3D40232324242426262626"
              password="71672F2B566E496D796E6168734D5977543378626A673D3D40232324242426262626"
              maxActive="100"
              maxIdle="30"
              maxWait="10000"
              initialSize="1"/>

#### Tomcat DBCP2 Connection Pool

    factory="org.apache.tomcat.dbcp.dbcp2.EncryptBasicDataSourceFactory"

>Please refer tomcat official document for detailed list of `Tomcat DBCP2 Connection Pool` attributes.  
>https://commons.apache.org/proper/commons-dbcp/configuration.html

###### Sample resource configuration: Before encryption

    <Resource name="jdbc/MSSQLDB"
              auth="Container"
              type="javax.sql.DataSource"
              fairQueue="true"
              singleton="true"
              driverClassName="com.microsoft.sqlserver.jdbc.SQLServerDriver"
              factory="org.apache.tomcat.dbcp.dbcp2.EncryptBasicDataSourceFactory"
              url="jdbc:sqlserver://localhost:1433;databaseName=mssqldb;SelectMethod=cursor;SendStringParametersAsUnicode=false;trustServerCertificate=true"
              username="mssqlUser"
              password="mssqlPassword"
              maxTotal="100"
              maxIdle="30"
              maxWaitMillis="10000"
              initialSize="1"/>

###### Generate encrypted values.

    $ java -jar tomcat-cp-encryption.jar -e "jdbc:sqlserver://localhost:1433;databaseName=mssqldb;SelectMethod=cursor;SendStringParametersAsUnicode=false;trustServerCertificate=true"
    encrypted: 386C335A784C2F682F77324C55414C3543576F51355536714E636B746E764639736B5A3757632F69715876643531583173586B444174454D49714D7A644E4279796D3259422F644C356F73536E58795333426D55656D5735507869597845694A75326D4D686F58384D5441346E36546D57326C316632727676543348625757535151466D747075576C667442727A556346393442685537464E6355786A62727553674F5131533766514531714E583237696863684D654A45515358316831765440232324242426262626
    $ java -jar tomcat-cp-encryption.jar -d "386C335A784C2F682F77324C55414C3543576F51355536714E636B746E764639736B5A3757632F69715876643531583173586B444174454D49714D7A644E4279796D3259422F644C356F73536E58795333426D55656D5735507869597845694A75326D4D686F58384D5441346E36546D57326C316632727676543348625757535151466D747075576C667442727A556346393442685537464E6355786A62727553674F5131533766514531714E583237696863684D654A45515358316831765440232324242426262626"
    decrypted: jdbc:sqlserver://localhost:1433;databaseName=mssqldb;SelectMethod=cursor;SendStringParametersAsUnicode=false;trustServerCertificate=true
    $ java -jar tomcat-cp-encryption.jar -e "mssqlUser"
    encrypted: 5837476D517479624B5335383446514F444D764B57413D3D40232324242426262626
    $ java -jar tomcat-cp-encryption.jar -d "5837476D517479624B5335383446514F444D764B57413D3D40232324242426262626"
    decrypted: mssqlUser
    $ java -jar tomcat-cp-encryption.jar -e "mssqlPassword"
    encrypted: 71672F2B566E496D796E6168734D5977543378626A673D3D40232324242426262626
    $ java -jar tomcat-cp-encryption.jar -d "71672F2B566E496D796E6168734D5977543378626A673D3D40232324242426262626"
    decrypted: mssqlPassword

###### Sample resource configuration after replacing with encrypted values

    <Resource name="jdbc/MSSQLDB"
              auth="Container"
              type="javax.sql.DataSource"
              fairQueue="true"
              singleton="true"
              driverClassName="com.microsoft.sqlserver.jdbc.SQLServerDriver"
              factory="org.apache.tomcat.dbcp.dbcp2.EncryptBasicDataSourceFactory"
              url="386C335A784C2F682F77324C55414C3543576F51355536714E636B746E764639736B5A3757632F69715876643531583173586B444174454D49714D7A644E4279796D3259422F644C356F73536E58795333426D55656D5735507869597845694A75326D4D686F58384D5441346E36546D57326C316632727676543348625757535151466D747075576C667442727A556346393442685537464E6355786A62727553674F5131533766514531714E583237696863684D654A45515358316831765440232324242426262626"          
              username="5837476D517479624B5335383446514F444D764B57413D3D40232324242426262626"
              password="71672F2B566E496D796E6168734D5977543378626A673D3D40232324242426262626"
              maxTotal="100"
              maxIdle="30"
              maxWaitMillis="10000"
              initialSize="1"/>

## Loggers

- `umrao.encrypt.Encryption` with `Level.SEVERE`
- `org.apache.tomcat.jdbc.pool.EncryptDataSourceFactory` with `Level.ALL`
- `org.apache.tomcat.dbcp.dbcp2.EncryptBasicDataSourceFactory` with `Level.ALL`

## Change Encryption Algorithm and Key

Modify `umrao.encrypt.Constants` according to your need and rebuild custom jar. You can modify below attributes
according to your need-

- `Encryption` algorithm
- `Hashing` algorithm
- Encryption `key`
- `IV`
