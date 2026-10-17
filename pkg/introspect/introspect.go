// Package introspect reads table, column, index and foreign key definitions
// from information_schema.
package introspect

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// Querier is the part of *sql.DB the package needs.
type Querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// Load reads the definitions of every table and view in the database.
func Load(ctx context.Context, q Querier, database string) (*model.Schema, error) {
	s := &model.Schema{Database: database}
	byName := map[string]*model.Table{}

	rows, err := q.QueryContext(ctx, `SELECT TABLE_NAME, TABLE_TYPE, IFNULL(ENGINE, ''),
		IFNULL(TABLE_ROWS, 0), IFNULL(DATA_LENGTH, 0), IFNULL(TABLE_COMMENT, '')
		FROM information_schema.TABLES WHERE TABLE_SCHEMA = ?`, database)
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	err = each(rows, func() error {
		t := &model.Table{}
		if err := rows.Scan(&t.Name, &t.Type, &t.Engine, &t.RowsEstimate, &t.DataBytes, &t.Comment); err != nil {
			return err
		}
		t.Type = strings.ToUpper(t.Type)
		s.Tables = append(s.Tables, t)
		byName[t.Name] = t
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}

	rows, err = q.QueryContext(ctx, `SELECT TABLE_NAME, COLUMN_NAME, ORDINAL_POSITION, DATA_TYPE, COLUMN_TYPE,
		IS_NULLABLE, CHARACTER_MAXIMUM_LENGTH, COLUMN_KEY, EXTRA, IFNULL(COLUMN_COMMENT, '')
		FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = ?`, database)
	if err != nil {
		return nil, fmt.Errorf("list columns: %w", err)
	}
	err = each(rows, func() error {
		var (
			table, nullable string
			maxLen          sql.NullInt64
			c               model.Column
		)
		if err := rows.Scan(&table, &c.Name, &c.Position, &c.DataType, &c.ColumnType,
			&nullable, &maxLen, &c.Key, &c.Extra, &c.Comment); err != nil {
			return err
		}
		c.DataType = strings.ToLower(c.DataType)
		c.Nullable = nullable == "YES"
		c.MaxLength = maxLen.Int64
		if t := byName[table]; t != nil {
			t.Columns = append(t.Columns, &c)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list columns: %w", err)
	}

	rows, err = q.QueryContext(ctx, `SELECT TABLE_NAME, INDEX_NAME, NON_UNIQUE, SEQ_IN_INDEX, COLUMN_NAME, SUB_PART, INDEX_TYPE
		FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = ?
		ORDER BY TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX`, database)
	if err != nil {
		return nil, fmt.Errorf("list indexes: %w", err)
	}
	err = each(rows, func() error {
		var (
			table, index string
			nonUnique    int
			seq          int
			column       sql.NullString
			subPart      sql.NullInt64
			indexType    sql.NullString
		)
		if err := rows.Scan(&table, &index, &nonUnique, &seq, &column, &subPart, &indexType); err != nil {
			return err
		}
		t := byName[table]
		if t == nil {
			return nil
		}
		if seq == 1 || len(t.Indexes) == 0 || t.Indexes[len(t.Indexes)-1].Name != index {
			t.Indexes = append(t.Indexes, model.Index{Name: index, Unique: nonUnique == 0, Type: strings.ToUpper(indexType.String)})
		}
		ix := &t.Indexes[len(t.Indexes)-1]
		ix.Columns = append(ix.Columns, column.String) // empty for functional key parts
		ix.SubParts = append(ix.SubParts, int(subPart.Int64))
		if index == "PRIMARY" && column.Valid {
			t.PrimaryKey = append(t.PrimaryKey, column.String)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list indexes: %w", err)
	}

	rows, err = q.QueryContext(ctx, `SELECT TABLE_NAME, CONSTRAINT_NAME, COLUMN_NAME,
		REFERENCED_TABLE_SCHEMA, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME
		FROM information_schema.KEY_COLUMN_USAGE
		WHERE TABLE_SCHEMA = ? AND REFERENCED_TABLE_NAME IS NOT NULL
		ORDER BY TABLE_NAME, CONSTRAINT_NAME, ORDINAL_POSITION`, database)
	if err != nil {
		return nil, fmt.Errorf("list foreign keys: %w", err)
	}
	err = each(rows, func() error {
		var table, name, column, refSchema, refTable, refColumn string
		if err := rows.Scan(&table, &name, &column, &refSchema, &refTable, &refColumn); err != nil {
			return err
		}
		t := byName[table]
		if t == nil {
			return nil
		}
		if n := len(t.ForeignKeys); n == 0 || t.ForeignKeys[n-1].Name != name {
			t.ForeignKeys = append(t.ForeignKeys, model.ForeignKey{Name: name, RefSchema: refSchema, RefTable: refTable})
		}
		fk := &t.ForeignKeys[len(t.ForeignKeys)-1]
		fk.Columns = append(fk.Columns, column)
		fk.RefColumns = append(fk.RefColumns, refColumn)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list foreign keys: %w", err)
	}

	sort.Slice(s.Tables, func(i, j int) bool { return s.Tables[i].Name < s.Tables[j].Name })
	for _, t := range s.Tables {
		sort.Slice(t.Columns, func(i, j int) bool { return t.Columns[i].Position < t.Columns[j].Position })
	}
	return s, nil
}

func each(rows *sql.Rows, fn func() error) error {
	defer rows.Close()
	for rows.Next() {
		if err := fn(); err != nil {
			return err
		}
	}
	return rows.Err()
}
