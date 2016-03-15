<?php

/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the
 * installation. You don't have to use the web site, you can
 * copy this file to "wp-config.php" and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://codex.wordpress.org/Editing_wp-config.php
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'db_name');

/** MySQL database username */
define('DB_USER', 'db_user');

/** MySQL database password */
define('DB_PASSWORD', 'db_pass');

/** MySQL hostname */
define('DB_HOST', 'localhost');

/** Database Charset to use in creating database tables. */
define('DB_CHARSET', 'utf8mb4');

/** The Database Collate type. Don't change this if in doubt. */
define('DB_COLLATE', '');

/**#@+
 * Authentication Unique Keys and Salts.
 *
 * Change these to different unique phrases!
 * You can generate these using the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}
 * You can change these at any point in time to invalidate all existing cookies. This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define('AUTH_KEY',         'mk.]Ww*5.@!37{(aU?Q622S+`ZTmG96Q`=WWR:B??9:#x]5jZ:1i#ni9[{R|A <(');
define('SECURE_AUTH_KEY',  'X@KCQgR2p! z<s0v|t;i7^rn5Vz_]=PN,ha6VN+I3P@Xt+ga2>M0bD*`?S8`-bS&');
define('LOGGED_IN_KEY',    '|LNE:$r!x:tPH2NOE=P .ck7z^jB5(gyim#4I]d1|N+xQZOfZx||?|&n3CuB}Szv');
define('NONCE_KEY',        'Kg1,5s-(yrD84@B;bPSKw-R)(~gT9)DLa)Ne-(>](OPMP0V@,We.Bq`+_Az<$BZt');
define('AUTH_SALT',        ';#DUg1{iH |#(`H=M9ielAII8+HhNp;#+gSdQ:w+s@8zLedo[^.8yP1G8#b%8j9U');
define('SECURE_AUTH_SALT', '=M[,zqL=a,M%9-Fn P>j=woc-?5`E)N.H!8,F|-+`8F{t%X5o-5VU8Vqx=i*K+l{');
define('LOGGED_IN_SALT',   'h=+AZ(Mrw|+~d%T(Mi1KiL`Ll-oqtW7&Dc.WU|w}BY>gep_8ym*^(bShAfVXa|t*');
define('NONCE_SALT',       'w$<;i1`f/43/jAO|j>7HnI3{ko&Y{@SzHQb)DklI4i!Q~E6lUV?mGt;SaYii[p!I');

/**#@-*/

/**
 * WordPress Database Table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix  = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the Codex.
 *
 * @link https://codex.wordpress.org/Debugging_in_WordPress
 */
define('WP_DEBUG', false);

/* That's all, stop editing! Happy blogging. */

/** Absolute path to the WordPress directory. */
if ( !defined('ABSPATH') )
	define('ABSPATH', dirname(__FILE__) . '/');

/** Sets up WordPress vars and included files. */
require_once(ABSPATH . 'wp-settings.php');

