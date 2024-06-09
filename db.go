package main

import (
	"fmt"
	"github.com/jackc/pgx"
	"os"
)

type Database struct {
	pool *pgx.Conn
}

func newDatabase() (*Database, error) {
	conn, err := pgx.Connect(
		pgx.ConnConfig{
			Host:     "localhost",
			Port:     5433,
			Database: "postgres",
			User:     os.Getenv("DB_USER"),
			Password: os.Getenv("DB_PASSWORD"),
		},
	)
	if err != nil {
		return nil, err
	}

	return &Database{
		pool: conn,
	}, nil
}

func (d *Database) initialize() error {
	createUserTable := `
	CREATE TABLE IF NOT EXISTS ips (
		ip TEXT NOT NULL UNIQUE
	)`

	if _, err := d.pool.Exec(createUserTable); err != nil {
		return fmt.Errorf("could not create ips table: %v", err)
	}

	return nil
}

func (d *Database) RetrieveIps() ([]string, error) {
	rows, err := d.pool.Query(`SELECT ip FROM ips`)
	if err != nil {
		return nil, fmt.Errorf("unable to execute select query: %w", err)
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err = rows.Scan(&ip); err != nil {
			return nil, fmt.Errorf("unable to scan row: %w", err)
		}
		ips = append(ips, ip)
	}

	if rows.Err() != nil {
		return nil, fmt.Errorf("row iteration error: %w", rows.Err())
	}

	return ips, nil
}

func (d *Database) InsertIp(ip string) error {
	_, err := d.pool.Exec(`INSERT INTO ips (ip) VALUES ($1)`, ip)
	if err != nil {
		return fmt.Errorf("unable to execute insert query: %w", err)
	}
	return nil
}
