package database

import (
	"context"
	"database/sql"
	"log"

	"rest-ws/models"

	_ "github.com/lib/pq"
)

type PostgresRepository struct {
	db *sql.DB
}

func NewPostgresRepository(url string) (*PostgresRepository, error) {
	db, err := sql.Open("postgres", url)

	if err != nil {
		return nil, err
	}

	return &PostgresRepository{
		db: db,
	}, nil
}

func (repo *PostgresRepository) InsertUser(ctx context.Context, user *models.User) error {

	_, err := repo.db.ExecContext(ctx, "INSERT INTO users (email, password) VALUES($1, $2)", user.Email, user.Password)

	return err

}

func (repo *PostgresRepository) GetUserById(ctx context.Context, id int64) (*models.User, error) {
	rows, err := repo.db.QueryContext(ctx, "SELECT id, email FROM users WHERE id=$1", id)

	defer func() {
		err = rows.Close()
		if err != nil {
			log.Fatal(err)
		}
	}()

	var user = models.User{}

	for rows.Next() {
		if err = rows.Scan(&user.Id, &user.Email); err == nil {
			return &user, nil
		}
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return &user, err
}

func (repo *PostgresRepository) Close() error {
	return repo.db.Close()
}
