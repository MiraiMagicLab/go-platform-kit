// Package transaction provides a generic PostgreSQL transaction helper.
//
// Usage:
//
//	err := transaction.WithTx(ctx, pool, func(ctx context.Context, tx pgx.Tx) error {
//	    // all operations in this function share the same transaction
//	    _, err := tx.Exec(ctx, "INSERT INTO ...", args...)
//	    return err
//	})
//
// To read the transaction from context (e.g., in a repository):
//
//	tx, ok := transaction.TxFromCtx(ctx)
//	if ok {
//	    // use tx
//	} else {
//	    // use pool directly
//	}
package transaction
