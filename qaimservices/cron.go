package qaimservices

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"qaimbe/qaimstructs"
	qs "qaimbe/qaimstructs"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func ResolveMaturedTokens(mailList map[string][]string, connPool *pgxpool.Pool) {
	/*
		Function runs daily, checks which user tokens have reached their
		maturity date and for each of them:
		1. extracts their matured value
		2. returns token back to the bond (transferring ownership to qaim)
		3. deposits value to respective users digital balance
		4. marks token as invalid
	*/
	tx, err := connPool.BeginTx(context.Background(), pgx.TxOptions{AccessMode: pgx.ReadWrite})
	if err != nil {
		fmt.Println("error beginning transaction", err)
		EmailErrorLog("ResolveMaturedTokens: Error beginning transaction", err.Error())
		return
	}
	defer tx.Rollback(context.TODO())
	_, err = tx.Exec(context.TODO(), `
		with agg_amount_for_bond AS (
			SELECT bond_id, SUM(amount_invested) AS bond_invested
			FROM PUBLIC.tbill_tokens
			WHERE valid = true AND NOW() >= maturity_date
			GROUP BY bond_id
		)
		-- 1. REPLENISH BONDS
		UPDATE PUBLIC.tbills AS a
		SET available_amount = available_amount + token.bond_invested
		FROM agg_amount_for_bond
		AS token
		WHERE token.bond_id = a.uuid
	`)
	if err != nil {
		fmt.Println("Error replenishing bonds", err)
		EmailErrorLog("MatureTbillTokens: Error replenishing tbills", err.Error())
		return
	}

	// NOTE(talha): get maturing tbills
	// it's inefficient because we do this operation again later
	// when updating tbills
	// There is no other easy way to get this data
	// and we need it for reporting
	rows, err := tx.Query(context.TODO(), `
		SELECT token_id, user_id, amount_invested, maturity_date, 
		tenor_days, bond_id, investment_date 
		FROM PUBLIC.tbill_tokens
		WHERE VALID = TRUE AND NOW() >= maturity_date
	`)
	if err != nil {
		fmt.Println("Error fetching matured tbill tokens", err)
		EmailErrorLog("Error fetching matured tbill tokens", err.Error())
		return
	}
	defer rows.Close()

	var maturingTokens []qaimstructs.TbillToken
	for rows.Next() {
		var token qaimstructs.TbillToken
		err = rows.Scan(&token.TokenId, &token.UserId, &token.AmountInvested, &token.MaturityDate,
			&token.TenorDays, &token.BondId, &token.InvestmentDate)
		if err != nil {
			fmt.Println("Error scanning maturing tbill tokens", err.Error())
			EmailErrorLog("MatureTbillTokens: Error scanning tbill tokens", err.Error())
			return
		}
		maturingTokens = append(maturingTokens, token)
	}

	_, err = tx.Exec(context.TODO(), `
		with invalidate_tokens AS ( -- 2. Update token status
			UPDATE PUBLIC.tbill_tokens
			SET VALID = false
			WHERE valid = true AND NOW() >= maturity_date
			RETURNING *
		), get_interest AS (
			SELECT inv.token_id, inv.amount_invested, inv.user_id, inv.tenor_days, ir.interest_rate
			FROM invalidate_tokens AS inv
			LEFT JOIN tbill_interest_rates AS ir ON inv.interest_id = ir.uuid
		), calc_tenor_frac AS (
			SELECT gi.token_id, SUM(gi.amount_invested) AS tot_inv, gi.user_id, gi.interest_rate,
			-- tenor_frac = (tenor_days|days_since_bought)/360(days in year per banks)
			gi.tenor_days/360.0 AS tenor_frac
			FROM get_interest AS gi
			GROUP BY gi.token_id, gi.user_id, gi.interest_rate, gi.tenor_days
		), calc_inv_return AS (
			SELECT tf.user_id,
				-- NOTE: tax_rate_percent_removed[tax rate is 15 - meaning (1-.15) = .85]
				-- tax_rate_percent_removed*investment*(tenor_frac*interest_rate - tenor_frac*1) [qaim holding rate is 1%]
				tf.tot_inv + FLOOR(0.85*tf.tot_inv*(
					(tf.tenor_frac*tf.interest_rate/100)-(tf.tenor_frac*1/100)
				)) AS inv_return
			FROM calc_tenor_frac AS tf
			GROUP BY tf.token_id, tf.user_id, tf.tot_inv, tf.interest_rate, tf.tenor_frac
		), calc_tot_inv AS (
			SELECT ir.user_id, SUM(ir.inv_return) AS u_return
			FROM calc_inv_return AS ir
			GROUP BY ir.user_id
		)
		
		UPDATE PUBLIC.user
		SET balance = balance + tot_inv.u_return
		FROM calc_tot_inv AS tot_inv
		WHERE uuid = tot_inv.user_id;
	`)
	if err != nil {
		fmt.Println("Error updating token and user balance", err)
		return
	}
	tx.Commit(context.TODO())
	// TODO(talha): Add maybe an email notification indicating that the cron job ran
	headers := []string{"Token Id", "User Id", "Amount Invested", "Maturity Date",
		"Tenor Days", "Bond Id", "Investment Date"}
	data := [][]string{headers}
	for i := 0; i < len(maturingTokens); i++ {
		token := maturingTokens[i]
		row := []string{
			token.TokenId, token.UserId, fmt.Sprint(token.AmountInvested), token.MaturityDate.String(),
			fmt.Sprint(token.TenorDays), token.BondId, token.InvestmentDate.String()}
		data = append(data, row)
	}
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	w.WriteAll(data)
	// * email csv
	go SendEmailBytes(mailList[MailReporting], SubjTbillMaturity, b)
}

func ResolveMaturedTbills(mailList map[string][]string, connPool *pgxpool.Pool) {
	// TODO(talha): make transaction
	rows, err := connPool.Query(context.TODO(), `
		UPDATE PUBLIC.tbills
		SET VALID = false
		WHERE VALID = TRUE AND maturity_date <= NOW()
		RETURNING uuid, tenor_days, issue_date, interest_rate, maturity_date, amount
	`)
	if err != nil {
		fmt.Println("error maturing tbills", err)
		EmailErrorLog("Error maturing tbills", err.Error())
		return
	}
	defer rows.Close()

	var resolvedTbills []qaimstructs.TbillBond
	for rows.Next() {
		var tbill qaimstructs.TbillBond
		err = rows.Scan(&tbill.Uuid, &tbill.TenorDays, &tbill.IssueDate, &tbill.InterestRate, &tbill.MaturityDate, &tbill.Amount)
		if err != nil {
			fmt.Println("error scanning tbills", err)
			EmailErrorLog("Error scanning matured tbills", err.Error())
			return
		}
		resolvedTbills = append(resolvedTbills, tbill)
	}

	headers := []string{"Tbill Id", "Tenor Days", "Issue Date", "Interest Rate", "Maturity Date", "Amount"}
	data := [][]string{headers}
	for i := 0; i < len(resolvedTbills); i++ {
		tbills := resolvedTbills[i]
		row := []string{
			tbills.Uuid, fmt.Sprint(tbills.TenorDays), tbills.IssueDate.String(),
			fmt.Sprint(tbills.InterestRate), tbills.MaturityDate.String(), fmt.Sprint(tbills.Amount)}
		data = append(data, row)
	}
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	w.WriteAll(data)
	// * email csv
	go SendEmailBytes(mailList[MailReporting], SubjTbillMaturity, b)
}

func ResolveTbills(mailList map[string][]string, connPool *pgxpool.Pool) {
	ResolveMaturedTokens(mailList, connPool)
	ResolveMaturedTbills(mailList, connPool)
}

func CustomerTbillHolding(mailList map[string][]string, connPool *pgxpool.Pool) {
	rows, err := connPool.Query(context.TODO(), `
		WITH get_interest_rate AS (
			SELECT ROW_NUMBER() OVER (ORDER BY tok.amount_invested) AS serial_num, tok.user_id, 
			tok.amount_invested, tok.investment_date, tok.maturity_date, 
			ir.interest_rate
			FROM PUBLIC.tbill_tokens AS tok
			LEFT JOIN PUBLIC.tbill_interest_rates AS ir
			ON tok.interest_id = ir.uuid
			WHERE Valid = TRUE
		)
		
		SELECT h.serial_num, h.user_id, 
		h.amount_invested, h.investment_date, h.maturity_date, 
		h.amount_invested + 
			FLOOR(h.amount_invested*(h.interest_rate/100.0)*
				DATE_PART('day', NOW()-h.investment_date)/360.0) AS value
		FROM get_interest_rate AS h;
	`)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer rows.Close()

	var userPurchases []qs.CsvTbillHolding
	for rows.Next() {
		var r qs.CsvTbillHolding
		err = rows.Scan(&r.SerialNumber, &r.UserId, &r.Amount, &r.InvestmentDate, &r.MaturityDate, &r.Value)
		if err != nil {
			fmt.Println(err)
			return
		}
		userPurchases = append(userPurchases, r)
	}

	// * Parse
	headers := []string{"Serial No.", "Customer ID", "Amount Invested", "Fraction Issue Date", "Fraction Maturity Date", "Current Value"}
	data := [][]string{headers}
	for i := 0; i < len(userPurchases); i++ {
		purch := userPurchases[i]
		row := []string{
			fmt.Sprint(purch.SerialNumber), purch.UserId, fmt.Sprint(purch.Amount),
			purch.InvestmentDate.String(), purch.MaturityDate.String(), fmt.Sprint(purch.Value)}
		data = append(data, row)
	}
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	w.WriteAll(data)
	// * email csv
	SendEmailBytes(mailList[MailReporting], SubjTbillHolding, b)
}

func CustomerTbillPurchase(mailList map[string][]string, connPool *pgxpool.Pool) {
	rows, err := connPool.Query(context.TODO(), `
		SELECT ROW_NUMBER() OVER (ORDER BY tok.amount_invested), NOW()::DATE, tok.user_id, u.national_id, tok.investment_date, tok.maturity_date, tok.amount_invested
		FROM PUBLIC.tbill_tokens AS tok
		LEFT JOIN PUBLIC.user AS u
		ON tok.user_id = u.uuid
		WHERE investment_date = NOW()::DATE AND Valid = TRUE;
	`)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer rows.Close()

	var userPurchases []qs.CsvTbillPurchase
	for rows.Next() {
		var r qs.CsvTbillPurchase
		err = rows.Scan(&r.SerialNumber, &r.Date, &r.UserId, &r.NationalId, &r.InvestmentDate, &r.MaturityDate, &r.Amount)
		if err != nil {
			fmt.Println(err)
			return
		}
		userPurchases = append(userPurchases, r)
	}

	// * Parse
	headers := []string{"Serial No.", "Date", "Customer Id", "CNIC", "Fraction Issue Date", "Fraction Maturity Date", "Value"}
	data := [][]string{headers}
	for i := 0; i < len(userPurchases); i++ {
		purch := userPurchases[i]
		row := []string{
			fmt.Sprint(purch.SerialNumber), purch.Date, purch.UserId, purch.NationalId,
			purch.InvestmentDate.String(), purch.MaturityDate.String(), fmt.Sprint(purch.Amount)}
		data = append(data, row)
	}
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	w.WriteAll(data)
	// * email csv
	SendEmailBytes(mailList[MailReporting], SubjTbillPurchase, b)
}

func CustomerWithdrawRequest(mailList map[string][]string, connPool *pgxpool.Pool) {
	rows, err := connPool.Query(context.TODO(), `
		SELECT ROW_NUMBER() OVER (ORDER BY wdraw.amount) AS row_number, wdraw.request_date, wdraw.user_id, u.national_id, u.iban, wdraw.amount
		FROM PUBLIC.user_withdraw_requests AS wdraw
		LEFT JOIN PUBLIC.user AS u 
		ON u.uuid = wdraw.user_id
		WHERE VALID = true;
	`)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer rows.Close()

	var userPurchases []qs.CsvWdrawRequest
	for rows.Next() {
		var r qs.CsvWdrawRequest
		err = rows.Scan(&r.SerialNumber, &r.Date, &r.UserId, &r.NationalId, &r.Iban, &r.Amount)
		if err != nil {
			fmt.Println(err)
			return
		}
		userPurchases = append(userPurchases, r)
	}

	// * Parse
	headers := []string{"Serial No.", "Date", "Customer Id", "CNIC", "IBAN", "Money Out Request"}
	data := [][]string{headers}
	for i := 0; i < len(userPurchases); i++ {
		purch := userPurchases[i]
		row := []string{fmt.Sprint(purch.SerialNumber), purch.Date.String(), purch.UserId, purch.NationalId, purch.Iban, fmt.Sprint(purch.Amount)}
		data = append(data, row)
	}
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	w.WriteAll(data)
	// * email csv
	SendEmailBytes(mailList[MailReporting], SubjFundsWithdraw, b)
}
