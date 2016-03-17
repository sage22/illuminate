<?php
// This script is a php script that can read any mysql statements into a database_name
// written to read a file in the same root folder "setusername.sql" and reset all the usernames for admin accounts for mysql
//Written by: Matthew Trotter --


$database_name = 'db_name';
$sqlFileToExecute = 'setusername.sql';
$hostname = 'localhost';
$db_username = 'root';
$db_pass = 'password';
$link = mysql_connect($hostname, $db_username, $db_pass);



if (!$link) {
  die ("MySQL Connection error");
}


// read the sql file
$f = fopen($sqlFileToExecute,"r+");
$sqlFile = fread($f, filesize($sqlFileToExecute));
$sqlArray = explode(';',$sqlFile);
foreach ($sqlArray as $stmt) {
  if (strlen($stmt)>3 && substr(ltrim($stmt),0,2)!='/*') {
    $result = mysql_query($stmt);
    if (!$result) {
      $sqlErrorCode = mysql_errno();
      $sqlErrorText = mysql_error();
      $sqlStmt = $stmt;
      break;
    }
  }
}
if ($sqlErrorCode == 0) {
  echo "Script is executed succesfully!";
} else {
  echo "An error occured during installation!<br/>";
  echo "Error code: $sqlErrorCode<br/>";
  echo "Error text: $sqlErrorText<br/>";
  echo "Statement:<br/> $sqlStmt<br/>";
}

?>
