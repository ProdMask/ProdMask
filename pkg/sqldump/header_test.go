package sqldump

import (
	"strings"
	"testing"
)

func TestHeader(t *testing.T) {
	tests := []struct {
		name, sql string
		want      Header
	}{
		{"mysqldump", `-- MySQL dump 10.13  Distrib 8.4.3, for Linux (x86_64)
--
-- Host: localhost    Database: shop
-- ------------------------------------------------------
-- Server version	8.4.3

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
CREATE TABLE t (a int);
`, Header{Producer: "mysqldump 8.4.3", Database: "shop", ServerVersion: "8.4.3"}},
		{"mariadb (its long producer line is shortened)", `/*M!999999\- enable the sandbox mode */
-- MariaDB dump 10.19  Distrib 10.11.6-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: shop
-- Server version	10.11.6-MariaDB
SET sql_mode='';
DROP TABLE t;
`, Header{Producer: "mariadb-dump 10.11.6", Database: "shop", ServerVersion: "10.11.6-MariaDB", MariaDB: true}},
		{"phpmyadmin", "-- phpMyAdmin SQL Dump\n-- version 5.2.1\n-- Server version: 8.0.30\n-- Database: `shop`\nDROP TABLE t;\n",
			Header{Producer: "phpMyAdmin", Database: "shop", ServerVersion: "8.0.30"}},
		{"mysqldump-php", "-- mysqldump-php https://github.com/ifsnop/mysqldump-php\n--\n-- Host: localhost\tDatabase: shop\n-- ------------------------------------------------------\n-- Server version \t5.7.40\nDROP TABLE t;\n",
			Header{Producer: "mysqldump-php", Database: "shop", ServerVersion: "5.7.40"}},
		{"nothing", "DROP TABLE t;", Header{}},
		{"a database name that fails the pattern", "-- Host: x    Database: sh op;drop\nDROP TABLE t;", Header{}},
		{"a database name with a quote", "-- Host: x    Database: sh'op\nDROP TABLE t;", Header{}},
		{"a version that is too long", "-- Server version\t" + strings.Repeat("1", 41) + "\nDROP TABLE t;", Header{}},
		{"a version at forty", "-- Server version\t" + strings.Repeat("1", 40) + "\nDROP TABLE t;", Header{ServerVersion: strings.Repeat("1", 40)}},
		{"a producer with other characters", "-- MySQL dump 10.13 \x1b[31mred\nDROP TABLE t;", Header{Producer: "MySQL dump 10.13"}},
		{"a producer too long", "-- MySQL dump " + strings.Repeat("9", 40) + "\nDROP TABLE t;", Header{}},
		{"later comments are not the header", "DROP TABLE t;\n-- Host: x    Database: late\n", Header{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, _ := readSQL(t, tc.sql)
			if v.hdrs != 1 || v.header != tc.want {
				t.Fatalf("header = %+v (sent %d times), want %+v", v.header, v.hdrs, tc.want)
			}
		})
	}
}

func TestHeaderSentOnce(t *testing.T) {
	v, _ := readSQL(t, "")
	if v.hdrs != 1 {
		t.Fatalf("an empty file sent the header %d times", v.hdrs)
	}
}

func TestHeaderFactPattern(t *testing.T) {
	for s, want := range map[string]bool{
		"shop": true, "a.b-c_d9": true, "": false, "a b": false, "a;b": false,
		strings.Repeat("a", 40): true, strings.Repeat("a", 41): false, "é": false,
	} {
		if validFact(s, false) != want {
			t.Errorf("validFact(%q) = %v", s, !want)
		}
	}
	if !validFact("MySQL dump 10.13", true) || validFact("MySQL dump 10.13", false) || validFact("a,b", true) {
		t.Error("spaces are allowed in the producer only")
	}
}

func TestHeaderProducerShortForms(t *testing.T) {
	for line, want := range map[string]string{
		"-- MySQL dump 10.13  Distrib 8.4.3, for Linux (x86_64)":                          "mysqldump 8.4.3",
		"-- MySQL dump 10.13  Distrib 5.7.44-log, for Linux (x86_64)":                     "mysqldump 5.7.44-log",
		"-- MariaDB dump 10.19  Distrib 11.8.2-MariaDB, for debian-linux-gnu (x86_64)":    "mariadb-dump 11.8.2",
		"-- MariaDB dump 10.19  Distrib 10.11.6-MariaDB-1:10.11.6+maria~ubu2204, for x86": "mariadb-dump 10.11.6",
		"-- MariaDB dump 10.20-11.8.9-MariaDB, for Win64 (AMD64)":                         "mariadb-dump 11.8.9",
		"-- mysqldump-php https://github.com/ifsnop/mysqldump-php":                        "mysqldump-php",
		"-- phpMyAdmin SQL Dump":                                                  "phpMyAdmin",
		"-- Adminer 4.8.1 MySQL 8.0.30 dump":                                      "Adminer 4.8.1",
		"-- Adminer zzcanaryhdr Ama Vexley 555-0100":                              "Adminer",
		"-- Sequel Ace 4.0.1 Ama Vexley":                                          "Sequel Ace 4.0.1",
		"-- MySQL dump 10.13 Ama Vexley 555-0100":                                 "MySQL dump 10.13",
		"-- MySQL dump 10.13  Distrib 8.4.3\x1b[31m, for Linux":                   "",
		"-- MySQL dump 10.13  Distrib " + strings.Repeat("9", 40) + ", for Linux": "",
	} {
		var h Header
		parseHeaderLine(line, &h)
		if h.Producer != want {
			t.Errorf("%q: producer %q, want %q", line, h.Producer, want)
		}
	}
}
