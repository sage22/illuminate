<?php
//This is a secure/ smart way to protect the $ _GET input from malicious injections and NULL values while passing strings via uri/and/or/url  from sql to mysql 
//: Written by Matthew Trotter sudirlay@icloud.com



// Here, php grabs info from url string, will not accept null values, if someone tries it toss the conn

 $varblogid = $_GET["blogid"];  
 if($_GET["blogid"] === "") die("Bad values");
 
 $varfbid = $_GET["fbid"];
 if($_GET["fbid"] === "")  die("Bad values");

 $vartwitid = $_GET["twitid"];
 if($_GET["twitid"] === "") die("Bad values");


//+++++++++++++++++++ Conditions for blocking suspicious injections on GET params - If somsone injects special char drop conn +++++++++++++++++++++++++++++


// Condition 1: Blogid only allowing numbers
 if (preg_match("/[da-zA-Z]/", $varblogid)) die("Bad values");     
 

// Conditions 2: Facebook id only allowing clean urls
if (preg_match("/[~`!@#$%^&*()_-+=\[\]{}\|\\:;\"\'<,>.]/", $varfbid)) die("Bad values");

//Condition 3: Twitter ID only allowing clean url
if (preg_match("/[~`!@#$%^&*()_-+=\[\]{}\|\\:;\"\'<,>.]/", $vartwitid)) die("Bad values");



// Echo this just testing purposes -  (silenced until needed then turn alive)
//exec("echo Blogid=$blogid passed parameters= $fbid $twitid into database successfully", $result); 

//print "<PRE>"; 

//foreach ($result as $r) { print "$r<BR>"; } 

//print "</PRE>";




//connects to a mysql server to run php query.

$servername = "IP.xxx.xxx.x";
$username = "username";
$password = "passxxx";
$dbname = "databasename";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

//Check connection
 if ($conn->connect_error) {
 die("Connection failed: " . $conn->connect_error);
}
// Run any sql statement calling variables 
$sql = "UPDATE {$varblogid}_options SET option_value='$varfbid'  WHERE  option_name='fb_fanpage'";


// Here, this will let front end know if sql query was successfully implemented or not
if ($conn->query($sql) === TRUE)
{
   echo "New record created successfully";
} else {
    echo "Error: " . $sql . "<br>" . $conn->error;
}

$conn->close();


?> 
