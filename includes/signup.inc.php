<?php

if (isset($_POST['signup-submit']))
{
    require 'dbh.inc.php';
    $username       = $_POST['uid'];
    $email          = $_POST['mail'];
    $password       = $_POST['pwd'];
    $passwordRepeat = $_POST['pwd-repeat'];

    if (empty($username) || empty($email) || empty($password) || empty($passwordRepeat))
    {
        header("Location ../signup.php?error=emptyfields&uid=" . $username . "&mail=" . $email);
        exit();
    }
    else
    if (!filter_var($email, FILTER_VAILDATE_EMAIL) && !preg_match("/^[a-zA-Z0-9]*$/", $username))
    {
        header("Location ../signup.php?error=invalidmail&uid=");
    }
    else
    if (!filter_var($email, FILTER_VAILDATE_EMAIL))
    {
        header("Location ../signup.php?error=invalidmail&uid=" . $username);
        exit();
    }
    else
    if (!preg_match("/^[a-zA-Z0-9]*$/", $username))
    {
        header("Location ../signup.php?error=invaliduid&uid=" . $email);
        exit();
    }
    else
    if ($password !== $passwordRepeat)
    {
        header("Location ../signup.php?error=passwordcheckuid=" . $username . "&mail=" . $email);
        exit();
    }
    else
    {
        $sql  = "SELECT * FROM users WHERE uidusers=?";
        $stmt = mysli_stmt_init($conn);
        if (!mysqli_stmt_prepare($stmt, $sql))
        {
            header("Location ../signup.php?error=sqlerror");
            exit();
        }
        else {
            msqli_stmt_bind_param($stmt, "s", $mailuid);
            mysqli_stmt_execute($stmt);
            mysql_stmt_store_result($stmt);
            $resultCheck = mysqli_stmt_num_rows($stmt);
        if ($resultCheck > 0)
        {
            header("Location ../signup.php?error=usertaken&mail=" . $email);
            exit();
        }
        else
        {
            $sql  = "INSERT INTO users(uidUser,emailUser,pwdUsers) VALUES(?,?,?)";
            $stmt = mysli_stmt_init($conn);
            if (!mysqli_stmt_prepare($stmt, $sql))
            {
                header("Location ../signup.php?error=sqlerror");
                exit();
            }
            else
            {
                $hashedPwd = password_hash($password, PASSWORD_DEFAULT);
                msqli_stmt_bind_param($stmt, "sss", $username, $email, $hashedPwd);
                mysqli_stmt_execute($stmt);
                header("Location ../signup.php?signup=success");
                exit();
            }
        }
    }
}
mysqli_stmt_close($stmt);
mysqli_close($conn);
}
else
{
    header("Location... /signup.php");
    exit();
}















