/*M!999999\- enable the sandbox mode */ 
-- MariaDB dump 10.20-11.8.9-MariaDB, for Win64 (AMD64)
--
-- Host: localhost    Database: prodmask_s10b_shapes
-- ------------------------------------------------------
-- Server version	11.8.9-MariaDB

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*M!100616 SET @OLD_NOTE_VERBOSITY=@@NOTE_VERBOSITY, NOTE_VERBOSITY=0 */;

--
-- Sequence structure for `shape_seq`
--

DROP SEQUENCE IF EXISTS `shape_seq`;
CREATE SEQUENCE `shape_seq` start with 100 minvalue 1 maxvalue 9223372036854775806 increment by 5 cache 1000 nocycle ENGINE=InnoDB;
DO SETVAL(`shape_seq`, 100, 0);

--
-- Table structure for table `shape_charsets`
--

DROP TABLE IF EXISTS `shape_charsets`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `shape_charsets` (
  `a` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
  `b` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
  `c` varchar(10) CHARACTER SET ascii COLLATE ascii_general_ci DEFAULT NULL,
  `d` text CHARACTER SET latin1 COLLATE latin1_bin DEFAULT NULL,
  `e` char(2) CHARACTER SET utf8mb3 COLLATE utf8mb3_uca1400_ai_ci DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `shape_charsets`
--

SET @OLD_AUTOCOMMIT=@@AUTOCOMMIT, @@AUTOCOMMIT=0;
LOCK TABLES `shape_charsets` WRITE;
/*!40000 ALTER TABLE `shape_charsets` DISABLE KEYS */;
INSERT INTO `shape_charsets` VALUES
('x','y','z','w','v');
/*!40000 ALTER TABLE `shape_charsets` ENABLE KEYS */;
UNLOCK TABLES;
COMMIT;
SET AUTOCOMMIT=@OLD_AUTOCOMMIT;

--
-- Table structure for table `shape_collate_only`
--

DROP TABLE IF EXISTS `shape_collate_only`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `shape_collate_only` (
  `a` varchar(10) DEFAULT NULL,
  `b` varchar(10) CHARACTER SET latin1 COLLATE latin1_swedish_ci DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `shape_collate_only`
--

SET @OLD_AUTOCOMMIT=@@AUTOCOMMIT, @@AUTOCOMMIT=0;
LOCK TABLES `shape_collate_only` WRITE;
/*!40000 ALTER TABLE `shape_collate_only` DISABLE KEYS */;
/*!40000 ALTER TABLE `shape_collate_only` ENABLE KEYS */;
UNLOCK TABLES;
COMMIT;
SET AUTOCOMMIT=@OLD_AUTOCOMMIT;

--
-- Table structure for table `shape_fk_child`
--

DROP TABLE IF EXISTS `shape_fk_child`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `shape_fk_child` (
  `id` int(11) NOT NULL,
  `parent_id` int(11) DEFAULT NULL,
  `parent_code` varchar(10) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_parent` (`parent_id`),
  KEY `fk_code` (`parent_code`),
  CONSTRAINT `fk_child_code` FOREIGN KEY (`parent_code`) REFERENCES `shape_fk_parent` (`code`) ON UPDATE CASCADE,
  CONSTRAINT `fk_child_parent` FOREIGN KEY (`parent_id`) REFERENCES `shape_fk_parent` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `shape_fk_child`
--

SET @OLD_AUTOCOMMIT=@@AUTOCOMMIT, @@AUTOCOMMIT=0;
LOCK TABLES `shape_fk_child` WRITE;
/*!40000 ALTER TABLE `shape_fk_child` DISABLE KEYS */;
INSERT INTO `shape_fk_child` VALUES
(1,1,'a'),
(2,2,'b');
/*!40000 ALTER TABLE `shape_fk_child` ENABLE KEYS */;
UNLOCK TABLES;
COMMIT;
SET AUTOCOMMIT=@OLD_AUTOCOMMIT;

--
-- Table structure for table `shape_fk_parent`
--

DROP TABLE IF EXISTS `shape_fk_parent`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `shape_fk_parent` (
  `id` int(11) NOT NULL,
  `code` varchar(10) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `code` (`code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `shape_fk_parent`
--

SET @OLD_AUTOCOMMIT=@@AUTOCOMMIT, @@AUTOCOMMIT=0;
LOCK TABLES `shape_fk_parent` WRITE;
/*!40000 ALTER TABLE `shape_fk_parent` DISABLE KEYS */;
INSERT INTO `shape_fk_parent` VALUES
(1,'a'),
(2,'b');
/*!40000 ALTER TABLE `shape_fk_parent` ENABLE KEYS */;
UNLOCK TABLES;
COMMIT;
SET AUTOCOMMIT=@OLD_AUTOCOMMIT;

--
-- Table structure for table `shape_fulltext`
--

DROP TABLE IF EXISTS `shape_fulltext`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `shape_fulltext` (
  `id` int(11) NOT NULL,
  `title` varchar(100) DEFAULT NULL,
  `body` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  FULLTEXT KEY `ft` (`title`,`body`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `shape_fulltext`
--

SET @OLD_AUTOCOMMIT=@@AUTOCOMMIT, @@AUTOCOMMIT=0;
LOCK TABLES `shape_fulltext` WRITE;
/*!40000 ALTER TABLE `shape_fulltext` DISABLE KEYS */;
/*!40000 ALTER TABLE `shape_fulltext` ENABLE KEYS */;
UNLOCK TABLES;
COMMIT;
SET AUTOCOMMIT=@OLD_AUTOCOMMIT;

--
-- Table structure for table `shape_generated`
--

DROP TABLE IF EXISTS `shape_generated`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `shape_generated` (
  `id` int(11) NOT NULL,
  `a` int(11) NOT NULL,
  `b` int(11) GENERATED ALWAYS AS (`a` + 1) VIRTUAL,
  `c` int(11) GENERATED ALWAYS AS (`a` * 2) STORED,
  `d` varchar(30) GENERATED ALWAYS AS (concat('x',`a`)) VIRTUAL,
  PRIMARY KEY (`id`),
  KEY `c` (`c`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `shape_generated`
--

SET @OLD_AUTOCOMMIT=@@AUTOCOMMIT, @@AUTOCOMMIT=0;
LOCK TABLES `shape_generated` WRITE;
/*!40000 ALTER TABLE `shape_generated` DISABLE KEYS */;
/*!40000 ALTER TABLE `shape_generated` ENABLE KEYS */;
UNLOCK TABLES;
COMMIT;
SET AUTOCOMMIT=@OLD_AUTOCOMMIT;

--
-- Table structure for table `shape_invisible`
--

DROP TABLE IF EXISTS `shape_invisible`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `shape_invisible` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `secret` varchar(30) DEFAULT NULL INVISIBLE,
  `plain` int(11) NOT NULL DEFAULT 7,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `shape_invisible`
--

SET @OLD_AUTOCOMMIT=@@AUTOCOMMIT, @@AUTOCOMMIT=0;
LOCK TABLES `shape_invisible` WRITE;
/*!40000 ALTER TABLE `shape_invisible` DISABLE KEYS */;
/*!40000 ALTER TABLE `shape_invisible` ENABLE KEYS */;
UNLOCK TABLES;
COMMIT;
SET AUTOCOMMIT=@OLD_AUTOCOMMIT;

--
-- Table structure for table `shape_keys`
--

DROP TABLE IF EXISTS `shape_keys`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `shape_keys` (
  `a` int(11) NOT NULL,
  `b` int(11) NOT NULL,
  `c` int(11) DEFAULT NULL,
  `d` int(11) NOT NULL,
  `e` int(11) DEFAULT NULL,
  PRIMARY KEY (`a`,`b`),
  UNIQUE KEY `uk_d` (`d`),
  UNIQUE KEY `uk_cd` (`c`,`d`),
  UNIQUE KEY `uk_e` (`e`),
  KEY `k_c` (`c`),
  KEY `k_ec` (`e`,`c`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `shape_keys`
--

SET @OLD_AUTOCOMMIT=@@AUTOCOMMIT, @@AUTOCOMMIT=0;
LOCK TABLES `shape_keys` WRITE;
/*!40000 ALTER TABLE `shape_keys` DISABLE KEYS */;
INSERT INTO `shape_keys` VALUES
(1,1,7,12,3),
(1,2,6,11,2),
(2,1,5,10,1);
/*!40000 ALTER TABLE `shape_keys` ENABLE KEYS */;
UNLOCK TABLES;
COMMIT;
SET AUTOCOMMIT=@OLD_AUTOCOMMIT;

--
-- Table structure for table `shape_latin1`
--

DROP TABLE IF EXISTS `shape_latin1`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `shape_latin1` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(40) CHARACTER SET latin1 COLLATE latin1_swedish_ci NOT NULL DEFAULT '',
  `note` text CHARACTER SET latin1 COLLATE latin1_swedish_ci DEFAULT NULL,
  `tag` char(3) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci COMMENT='a latin1 column';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `shape_latin1`
--

SET @OLD_AUTOCOMMIT=@@AUTOCOMMIT, @@AUTOCOMMIT=0;
LOCK TABLES `shape_latin1` WRITE;
/*!40000 ALTER TABLE `shape_latin1` DISABLE KEYS */;
INSERT INTO `shape_latin1` VALUES
(1,'José','a note','ab'),
(2,'Ann',NULL,NULL),
(3,'it\'s','back\\slash','x');
/*!40000 ALTER TABLE `shape_latin1` ENABLE KEYS */;
UNLOCK TABLES;
COMMIT;
SET AUTOCOMMIT=@OLD_AUTOCOMMIT;
/*!50003 SET @saved_cs_client      = @@character_set_client */ ;
/*!50003 SET @saved_cs_results     = @@character_set_results */ ;
/*!50003 SET @saved_col_connection = @@collation_connection */ ;
/*!50003 SET character_set_client  = utf8mb4 */ ;
/*!50003 SET character_set_results = utf8mb4 */ ;
/*!50003 SET collation_connection  = utf8mb4_uca1400_ai_ci */ ;
/*!50003 SET @saved_sql_mode       = @@sql_mode */ ;
/*!50003 SET sql_mode              = 'ANSI_QUOTES,NO_BACKSLASH_ESCAPES,STRICT_TRANS_TABLES' */ ;
DELIMITER ;;
/*!50003 CREATE*/ /*!50017 DEFINER="root"@"localhost"*/ /*!50003 TRIGGER shape_trigger BEFORE INSERT ON shape_latin1 FOR EACH ROW SET NEW.name = "x" 
*/;;
DELIMITER ;
/*!50003 SET sql_mode              = @saved_sql_mode */ ;
/*!50003 SET character_set_client  = @saved_cs_client */ ;
/*!50003 SET character_set_results = @saved_cs_results */ ;
/*!50003 SET collation_connection  = @saved_col_connection */ ;

--
-- Table structure for table `shape_latin1_table`
--

DROP TABLE IF EXISTS `shape_latin1_table`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `shape_latin1_table` (
  `id` int(11) NOT NULL,
  `name` varchar(40) NOT NULL,
  `kind` enum('a','bb','ccc') NOT NULL DEFAULT 'a',
  `flags` set('x','yy') DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `shape_latin1_table`
--

SET @OLD_AUTOCOMMIT=@@AUTOCOMMIT, @@AUTOCOMMIT=0;
LOCK TABLES `shape_latin1_table` WRITE;
/*!40000 ALTER TABLE `shape_latin1_table` DISABLE KEYS */;
/*!40000 ALTER TABLE `shape_latin1_table` ENABLE KEYS */;
UNLOCK TABLES;
COMMIT;
SET AUTOCOMMIT=@OLD_AUTOCOMMIT;

--
-- Table structure for table `shape_memory`
--

DROP TABLE IF EXISTS `shape_memory`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `shape_memory` (
  `a` int(11) NOT NULL,
  `b` varchar(10) DEFAULT NULL,
  KEY `k_a` (`a`),
  KEY `k_b` (`b`) USING BTREE
) ENGINE=MEMORY DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `shape_memory`
--

SET @OLD_AUTOCOMMIT=@@AUTOCOMMIT, @@AUTOCOMMIT=0;
LOCK TABLES `shape_memory` WRITE;
/*!40000 ALTER TABLE `shape_memory` DISABLE KEYS */;
INSERT INTO `shape_memory` VALUES
(2,'m'),
(1,'n');
/*!40000 ALTER TABLE `shape_memory` ENABLE KEYS */;
UNLOCK TABLES;
COMMIT;
SET AUTOCOMMIT=@OLD_AUTOCOMMIT;

--
-- Table structure for table `shape_myisam`
--

DROP TABLE IF EXISTS `shape_myisam`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `shape_myisam` (
  `a` int(11) NOT NULL,
  `b` varchar(10) DEFAULT NULL,
  KEY `k_a` (`a`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `shape_myisam`
--

SET @OLD_AUTOCOMMIT=@@AUTOCOMMIT, @@AUTOCOMMIT=0;
LOCK TABLES `shape_myisam` WRITE;
/*!40000 ALTER TABLE `shape_myisam` DISABLE KEYS */;
INSERT INTO `shape_myisam` VALUES
(2,'m'),
(1,'n');
/*!40000 ALTER TABLE `shape_myisam` ENABLE KEYS */;
UNLOCK TABLES;
COMMIT;
SET AUTOCOMMIT=@OLD_AUTOCOMMIT;

--
-- Table structure for table `shape_nopk`
--

DROP TABLE IF EXISTS `shape_nopk`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `shape_nopk` (
  `a` int(11) DEFAULT NULL,
  `b` varchar(10) DEFAULT NULL,
  `c` varchar(10) DEFAULT NULL,
  KEY `a` (`a`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `shape_nopk`
--

SET @OLD_AUTOCOMMIT=@@AUTOCOMMIT, @@AUTOCOMMIT=0;
LOCK TABLES `shape_nopk` WRITE;
/*!40000 ALTER TABLE `shape_nopk` DISABLE KEYS */;
INSERT INTO `shape_nopk` VALUES
(3,'c','z'),
(1,'a','y'),
(2,'b','x'),
(NULL,NULL,NULL);
/*!40000 ALTER TABLE `shape_nopk` ENABLE KEYS */;
UNLOCK TABLES;
COMMIT;
SET AUTOCOMMIT=@OLD_AUTOCOMMIT;

--
-- Table structure for table `shape_partitioned`
--

DROP TABLE IF EXISTS `shape_partitioned`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `shape_partitioned` (
  `id` int(11) NOT NULL,
  `created` date NOT NULL,
  `note` varchar(20) DEFAULT NULL,
  PRIMARY KEY (`id`,`created`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
 PARTITION BY RANGE (year(`created`))
(PARTITION `p0` VALUES LESS THAN (2020) ENGINE = InnoDB,
 PARTITION `p1` VALUES LESS THAN MAXVALUE ENGINE = InnoDB);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `shape_partitioned`
--

SET @OLD_AUTOCOMMIT=@@AUTOCOMMIT, @@AUTOCOMMIT=0;
LOCK TABLES `shape_partitioned` WRITE;
/*!40000 ALTER TABLE `shape_partitioned` DISABLE KEYS */;
/*!40000 ALTER TABLE `shape_partitioned` ENABLE KEYS */;
UNLOCK TABLES;
COMMIT;
SET AUTOCOMMIT=@OLD_AUTOCOMMIT;

--
-- Table structure for table `shape_prefix`
--

DROP TABLE IF EXISTS `shape_prefix`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `shape_prefix` (
  `id` int(11) NOT NULL,
  `email` varchar(255) DEFAULT NULL,
  `body` text DEFAULT NULL,
  UNIQUE KEY `u` (`email`(10)),
  KEY `email_prefix` (`email`(20)),
  KEY `body_prefix` (`body`(30)),
  KEY `whole` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `shape_prefix`
--

SET @OLD_AUTOCOMMIT=@@AUTOCOMMIT, @@AUTOCOMMIT=0;
LOCK TABLES `shape_prefix` WRITE;
/*!40000 ALTER TABLE `shape_prefix` DISABLE KEYS */;
/*!40000 ALTER TABLE `shape_prefix` ENABLE KEYS */;
UNLOCK TABLES;
COMMIT;
SET AUTOCOMMIT=@OLD_AUTOCOMMIT;

--
-- Table structure for table `shape_promoted`
--

DROP TABLE IF EXISTS `shape_promoted`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `shape_promoted` (
  `a` int(11) NOT NULL,
  `b` int(11) DEFAULT NULL,
  `c` int(11) NOT NULL,
  UNIQUE KEY `uk_a` (`a`),
  UNIQUE KEY `uk_c` (`c`),
  KEY `k_b` (`b`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `shape_promoted`
--

SET @OLD_AUTOCOMMIT=@@AUTOCOMMIT, @@AUTOCOMMIT=0;
LOCK TABLES `shape_promoted` WRITE;
/*!40000 ALTER TABLE `shape_promoted` DISABLE KEYS */;
/*!40000 ALTER TABLE `shape_promoted` ENABLE KEYS */;
UNLOCK TABLES;
COMMIT;
SET AUTOCOMMIT=@OLD_AUTOCOMMIT;

--
-- Table structure for table `shape_promoted_composite`
--

DROP TABLE IF EXISTS `shape_promoted_composite`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `shape_promoted_composite` (
  `a` int(11) NOT NULL,
  `b` int(11) NOT NULL,
  UNIQUE KEY `uk_ab` (`a`,`b`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `shape_promoted_composite`
--

SET @OLD_AUTOCOMMIT=@@AUTOCOMMIT, @@AUTOCOMMIT=0;
LOCK TABLES `shape_promoted_composite` WRITE;
/*!40000 ALTER TABLE `shape_promoted_composite` DISABLE KEYS */;
/*!40000 ALTER TABLE `shape_promoted_composite` ENABLE KEYS */;
UNLOCK TABLES;
COMMIT;
SET AUTOCOMMIT=@OLD_AUTOCOMMIT;

--
-- Table structure for table `shape_spatial`
--

DROP TABLE IF EXISTS `shape_spatial`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `shape_spatial` (
  `id` int(11) NOT NULL,
  `g` geometry NOT NULL,
  PRIMARY KEY (`id`),
  SPATIAL KEY `sp` (`g`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `shape_spatial`
--

SET @OLD_AUTOCOMMIT=@@AUTOCOMMIT, @@AUTOCOMMIT=0;
LOCK TABLES `shape_spatial` WRITE;
/*!40000 ALTER TABLE `shape_spatial` DISABLE KEYS */;
/*!40000 ALTER TABLE `shape_spatial` ENABLE KEYS */;
UNLOCK TABLES;
COMMIT;
SET AUTOCOMMIT=@OLD_AUTOCOMMIT;

--
-- Table structure for table `shape_sysver`
--

DROP TABLE IF EXISTS `shape_sysver`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `shape_sysver` (
  `id` int(11) NOT NULL,
  `v` varchar(10) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci WITH SYSTEM VERSIONING;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `shape_sysver`
--

SET @OLD_AUTOCOMMIT=@@AUTOCOMMIT, @@AUTOCOMMIT=0;
LOCK TABLES `shape_sysver` WRITE;
/*!40000 ALTER TABLE `shape_sysver` DISABLE KEYS */;
/*!40000 ALTER TABLE `shape_sysver` ENABLE KEYS */;
UNLOCK TABLES;
COMMIT;
SET AUTOCOMMIT=@OLD_AUTOCOMMIT;

--
-- Table structure for table `shape_types`
--

DROP TABLE IF EXISTS `shape_types`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `shape_types` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `flag` tinyint(1) NOT NULL DEFAULT 0,
  `price` decimal(10,2) NOT NULL DEFAULT 0.00,
  `ratio` float DEFAULT NULL,
  `big` double DEFAULT NULL,
  `bits` bit(3) DEFAULT NULL,
  `born` date DEFAULT NULL,
  `seen` datetime(3) NOT NULL DEFAULT current_timestamp(3),
  `touched` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `touched6` timestamp(6) NULL DEFAULT NULL ON UPDATE current_timestamp(6),
  `yr` year(4) DEFAULT NULL,
  `at` time(2) DEFAULT NULL,
  `doc` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`doc`)),
  `blob_a` blob DEFAULT NULL,
  `blob_l` longblob DEFAULT NULL,
  `text_m` mediumtext DEFAULT NULL,
  `text_t` tinytext DEFAULT NULL,
  `text_l` longtext DEFAULT NULL,
  `bin` binary(16) DEFAULT NULL,
  `vbin` varbinary(20) DEFAULT NULL,
  `one` char(1) NOT NULL DEFAULT 'x',
  `kind` enum('red','green','blue') NOT NULL DEFAULT 'green',
  `picks` set('a','bb','ccc') DEFAULT NULL,
  `quote` varchar(10) NOT NULL DEFAULT 'it''s',
  `num` int(11) NOT NULL DEFAULT -5,
  `nul` int(11) DEFAULT NULL,
  `cmt` int(11) DEFAULT NULL COMMENT 'with ''quotes''',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='table comment';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `shape_types`
--

SET @OLD_AUTOCOMMIT=@@AUTOCOMMIT, @@AUTOCOMMIT=0;
LOCK TABLES `shape_types` WRITE;
/*!40000 ALTER TABLE `shape_types` DISABLE KEYS */;
INSERT INTO `shape_types` VALUES
(1,1,12.50,1.5,2.25,NULL,'2020-02-03','2026-11-20 10:22:00.720','2026-11-20 08:22:00',NULL,NULL,NULL,'{\"a\": 1}','raw',NULL,'medium',NULL,NULL,'abcdefghijklmnop',NULL,'y','red','a,bb','it\'s',3,NULL,NULL),
(2,0,0.00,NULL,NULL,NULL,NULL,'2026-11-20 10:22:00.720','2026-11-20 08:22:00',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'x','green',NULL,'it\'s',-5,NULL,NULL);
/*!40000 ALTER TABLE `shape_types` ENABLE KEYS */;
UNLOCK TABLES;
COMMIT;
SET AUTOCOMMIT=@OLD_AUTOCOMMIT;

--
-- Table structure for table `shape_unique_null`
--

DROP TABLE IF EXISTS `shape_unique_null`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `shape_unique_null` (
  `a` int(11) DEFAULT NULL,
  `b` int(11) DEFAULT NULL,
  UNIQUE KEY `uk_a` (`a`),
  UNIQUE KEY `uk_ab` (`a`,`b`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `shape_unique_null`
--

SET @OLD_AUTOCOMMIT=@@AUTOCOMMIT, @@AUTOCOMMIT=0;
LOCK TABLES `shape_unique_null` WRITE;
/*!40000 ALTER TABLE `shape_unique_null` DISABLE KEYS */;
/*!40000 ALTER TABLE `shape_unique_null` ENABLE KEYS */;
UNLOCK TABLES;
COMMIT;
SET AUTOCOMMIT=@OLD_AUTOCOMMIT;

--
-- Table structure for table `shape_uuid`
--

DROP TABLE IF EXISTS `shape_uuid`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `shape_uuid` (
  `id` int(11) NOT NULL,
  `u` uuid DEFAULT uuid(),
  `j` longtext DEFAULT NULL CHECK (json_valid(`j`)),
  `d` date DEFAULT curdate(),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `shape_uuid`
--

SET @OLD_AUTOCOMMIT=@@AUTOCOMMIT, @@AUTOCOMMIT=0;
LOCK TABLES `shape_uuid` WRITE;
/*!40000 ALTER TABLE `shape_uuid` DISABLE KEYS */;
/*!40000 ALTER TABLE `shape_uuid` ENABLE KEYS */;
UNLOCK TABLES;
COMMIT;
SET AUTOCOMMIT=@OLD_AUTOCOMMIT;

--
-- Temporary table structure for view `shape_view`
--

DROP TABLE IF EXISTS `shape_view`;
/*!50001 DROP VIEW IF EXISTS `shape_view`*/;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8mb4;
/*!50001 CREATE VIEW `shape_view` AS SELECT
 NULL AS `id`,
 NULL AS `name` */;
SET character_set_client = @saved_cs_client;

--
-- Final view structure for view `shape_view`
--

/*!50001 DROP VIEW IF EXISTS `shape_view`*/;
/*!50001 SET @saved_cs_client          = @@character_set_client */;
/*!50001 SET @saved_cs_results         = @@character_set_results */;
/*!50001 SET @saved_col_connection     = @@collation_connection */;
/*!50001 SET character_set_client      = utf8mb4 */;
/*!50001 SET character_set_results     = utf8mb4 */;
/*!50001 SET collation_connection      = utf8mb4_uca1400_ai_ci */;
/*!50001 CREATE ALGORITHM=UNDEFINED */
/*!50013 DEFINER=`root`@`localhost` SQL SECURITY DEFINER */
/*!50001 VIEW `shape_view` AS select `shape_latin1`.`id` AS `id`,`shape_latin1`.`name` AS `name` from `shape_latin1` */;
/*!50001 SET character_set_client      = @saved_cs_client */;
/*!50001 SET character_set_results     = @saved_cs_results */;
/*!50001 SET collation_connection      = @saved_col_connection */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*M!100616 SET NOTE_VERBOSITY=@OLD_NOTE_VERBOSITY */;

-- Dump completed on 2026-11-20 10:22:01
