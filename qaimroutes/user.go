package qaimroutes

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	qservices "qaimbe/qaimservices"
	qstructs "qaimbe/qaimstructs"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

func extractUserIdFromToken(w http.ResponseWriter, r *http.Request) (string, error) {
	token := r.Header.Get("Token")
	subjId, err := qservices.GetJwtSubject(token)
	if err != nil {
		fmt.Println(err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return "", nil
	}
	return subjId, nil
}

func postUserSignup(w http.ResponseWriter, r *http.Request, connPool *pgxpool.Pool) {
	if !qservices.ValidateContentType(r, qservices.ContentMultipartForm) {
		http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
		return
	}
	var u qstructs.User
	/*
		* Writing file steps:
		- using a specific directory
		- check if dir exists
		- create dir
		-
	*/
	_ = r.ParseMultipartForm(0)
	u.NationalId = r.PostFormValue("nationalId")
	u.FirstName = r.PostFormValue("firstName")
	u.LastName = r.PostFormValue("lastName")
	u.PhoneNum = r.PostFormValue("phoneNum")
	u.Password = r.PostFormValue("password")
	u.Iban = r.PostFormValue("iban")

	// input validation
	if !qservices.ValidateName(u.FirstName) {
		http.Error(w, "Incorrect first name", http.StatusBadRequest)
		return
	}
	if !qservices.ValidateName(u.LastName) {
		http.Error(w, "Incorrect last name", http.StatusBadRequest)
		return
	}
	if !qservices.ValidatePhoneNum(u.PhoneNum) {
		http.Error(w,
			"Invalid phonenumber",
			http.StatusBadRequest)
		return
	}
	if !qservices.ValidateNationalId(u.NationalId) {
		http.Error(w,
			"Invalid national id",
			http.StatusBadRequest)
		return
	}
	if !qservices.ValidatePassword(u.Password) {
		http.Error(w,
			`Password needs to be greater than 8 digits,
			and cannot contain the following characters: .,*,\,\t,\n,\r,',",>,<,`,
			http.StatusBadRequest)
		return
	}
	if !qservices.ValidateIban(u.Iban) {
		http.Error(w,
			"Invalid IBAN format",
			http.StatusBadRequest)
		return
	}
	imgF, imgFheader, err := r.FormFile("idFront")
	if err != nil {
		fmt.Fprintln(w, "Error reading front id card")
		return
	}
	if !qservices.ValidateImage(imgFheader) {
		http.Error(w,
			"Invalid front id card image, only jpeg and pngs < 2mb allowed",
			http.StatusBadRequest)
		return
	}
	imgB, imgBheader, err := r.FormFile("idBack")
	if err != nil {
		fmt.Fprintln(w, "Error reading back id card")
		return
	}
	if !qservices.ValidateImage(imgBheader) {
		http.Error(w,
			"Invalid back id card image, only jpeg and pngs < 2mb",
			http.StatusBadRequest)
		return
	}
	if imgF == nil || imgB == nil {
		http.Error(w,
			"Missing id card image(s)",
			http.StatusBadRequest)
		return
	}

	// TODO: add channels to UploadToS3 function to make uploads concurrent
	fname := imgFheader.Filename
	flind := strings.LastIndexAny(fname, ".")
	fpath := "id_cards/" + u.NationalId + "id_front" + fname[flind:]
	err = qservices.UploadToS3(imgF, fpath)
	if err != nil {
		fmt.Fprintln(w, "error uploading file", err)
		errorStr := fmt.Sprintf("Error occurred for user:\n%s, %s, %s, %s, %s", u.NationalId, u.FirstName, u.LastName, u.PhoneNum, u.Iban)
		go qservices.EmailErrorLog(qservices.SubjSignupErr, errorStr)
		return
	}

	bname := imgBheader.Filename
	blind := strings.LastIndexAny(bname, ".")
	bpath := "id_cards/" + u.NationalId + "id_back" + bname[blind:]
	err = qservices.UploadToS3(imgB, bpath)
	if err != nil {
		fmt.Fprintln(w, "error uploading file", err)
		errorStr := fmt.Sprintf("Error occurred for user:\n%s, %s, %s, %s, %s", u.NationalId, u.FirstName, u.LastName, u.PhoneNum, u.Iban)
		go qservices.EmailErrorLog(qservices.SubjSignupErr, errorStr)
		return
	}

	fmt.Fprintf(w, "signup attempting for user %v\n", u)
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("error generating password")
		passwErr := fmt.Sprintf("error generating password hash:\n %s %s %s %s", u.NationalId, u.FirstName, u.LastName, u.PhoneNum)
		go qservices.EmailErrorLog(qservices.SubjSignupErr, passwErr)
		return
	}
	// QUERY EXECUTION
	_, err = connPool.Exec(
		context.Background(),
		"INSERT INTO public.user (uuid, national_id, first_name, last_name, phone_number, iban, id_front, id_back, password_hash, verified) VALUES ((SELECT gen_random_uuid()), $1, $2, $3, $4, $5, $6, $7, $8, $9)",
		u.NationalId, u.FirstName, u.LastName, u.PhoneNum, u.Iban, fpath, bpath, hashedPass, false)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Error occurred during sign up", http.StatusInternalServerError)
		errorStr := fmt.Sprintf("Error occurred for user:\n%s, %s, %s, %s, %s", u.NationalId, u.FirstName, u.LastName, u.PhoneNum, u.Iban)
		go qservices.EmailErrorLog(qservices.SubjSignupErr, errorStr)
		return
	}
	fmt.Fprintln(w, "User added successfully")
	mailingList := *qservices.GlobalState.MailList
	notifierList := mailingList[qservices.MailUserNotifier]
	message := fmt.Sprintf("National Id, First Name, Last Name, Phone Number, Iban\n%s, %s, %s, %s, %s", u.NationalId, u.FirstName, u.LastName, u.PhoneNum, u.Iban)
	go qservices.SendEmailString(notifierList, qservices.SubjUserSignup, message)
}

func postUserLogin(w http.ResponseWriter, r *http.Request, connPool *pgxpool.Pool) {
	if !qservices.ValidateContentType(r, qservices.ContentJson) {
		http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
		return
	}
	var u qstructs.User
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&u)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	}
	if !qservices.ValidatePhoneNum(u.PhoneNum) {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if !qservices.ValidatePassword(u.Password) {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	var auth qstructs.UserAuth
	var verified bool = true
	err = connPool.QueryRow(context.Background(), "select uuid, password_hash, national_id, verified from public.user where phone_number=$1", u.PhoneNum).Scan(&auth.Uuid, &auth.PasswordHash, &auth.NationalId, &verified)
	if err != nil {
		if err.Error() != qservices.StatusEmptyRequest {
			fmt.Fprintf(os.Stderr, "Query failed: %v\n", err)
			// TODO(talha): implement a better way of exiting the program
			return
		}
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if !verified {
		fmt.Fprintln(w, "User is not verified, user verification may take upto 1-2 days for verification")
		return
	}

	err = bcrypt.CompareHashAndPassword(auth.PasswordHash, []byte(u.Password))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	token, err := qservices.CreateJwtToken(auth.Uuid, qservices.USER)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
	fmt.Fprintf(w, "You are logged in\nuserId: %s\njwtToken: %s", auth.Uuid, token.Token)
}

func getInterestRate(w http.ResponseWriter, r *http.Request, connPool *pgxpool.Pool) {
	var ir qstructs.TbillInterestRate
	var dbDate time.Time
	err := connPool.QueryRow(context.Background(), "select interest_rate, date from public.tbill_interest_rates ORDER BY DATE DESC LIMIT 1;").Scan(&ir.InterestRate, &dbDate)
	if err != nil {
		if err.Error() != qservices.StatusEmptyRequest {
			fmt.Fprintf(os.Stderr, "Query failed: %v\n", err)
		} else {
			fmt.Fprintln(w, "No interest rate exists")
		}
		go qservices.EmailErrorLog(qservices.SubjGetInterestRateErr, err.Error())
		return
	}
	ir.Date = dbDate.UTC().Format(time.RFC3339)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "date: %s\ninterest rate: %f\n", ir.Date, ir.InterestRate)
}

func postTbillPurchase(w http.ResponseWriter, r *http.Request, connPool *pgxpool.Pool) {
	/*
		User specifies:
		* user_id
		* Amount to invest:
		1. amount > 1000
		2. optional: but we can artificially cap this to a 1000
		* tenor_days
	*/
	if !qservices.ValidateContentType(r, qservices.ContentJson) {
		http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
		return
	}
	userId, err := extractUserIdFromToken(w, r)
	if err != nil {
		return
	}
	// parse json body
	var user qstructs.TbillToken
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&user)
	user.UserId = userId
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	errMsg := ""
	invalidData := false
	if user.AmountInvested < 1000 || user.AmountInvested > 50000 {
		errMsg += "invalid investment amount, \namount >= 1000 pkr OR amount <= 10,000 pkr\n"
		invalidData = true
	}
	if user.AmountInvested%500 != 0 {
		errMsg += "invalid investment amount, \ncan only invest in multiples of 500 pkr\n"
		invalidData = true
	}
	if user.TenorDays != 90 && user.TenorDays != 180 && user.TenorDays != 270 {
		errMsg += "incorrect tenor days, \nsupported tenor days are: 90, 180, 270\n"
		invalidData = true
	}
	if invalidData {
		http.Error(w, errMsg, http.StatusBadRequest)
		return
	}
	tx, err := connPool.BeginTx(context.Background(), pgx.TxOptions{AccessMode: pgx.ReadWrite})
	if err != nil {
		fmt.Println("error beginning transaction", err)
		qservices.EmailErrorLog("ResolveMaturedTokens: Error beginning transaction", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(context.TODO())
	// ----------------------------------------
	// $1 = user_id, $2 = tenor_days, $3 = buying_amount
	cmdTag, err := tx.Exec(context.TODO(), `
	WITH get_interest_rate AS (
		SELECT uuid AS ir_id, date as ir_date, interest_rate as ir_ir FROM PUBLIC.tbill_interest_rates
		ORDER BY DATE DESC
		LIMIT 1	
	), get_available_tbills AS (
		SELECT (
		SUM(available_amount) OVER 
		(ORDER BY tenor_days rows between unbounded preceding and current row)
		) AS avail_running, * 
		FROM PUBLIC.tbills 
		WHERE maturity_date >= (NOW() + make_interval(0, 0, 0, $2))::DATE
		AND (
			$3 <= (
				SELECT balance FROM PUBLIC.user WHERE uuid = $1
			)
		)
	), get_tbills_for_tokens AS (
		SELECT NOW() AS buying_date, uuid AS bond_id, 
		available_amount, avail_running, 
		(NOW() + make_interval(0, 0, 0, $2))::DATE AS token_maturity_date,
		GREATEST(0, avail_running - $3) AS updated_available_amount,
		LEAST(available_amount, $3 - 
			(
				CASE
					WHEN LAG(avail_running, 1) OVER (ORDER BY avail_running) IS NULL THEN 0
					WHEN LAG(avail_running, 1) OVER (ORDER BY avail_running) >= 0 THEN LAG(avail_running, 1) OVER (ORDER BY avail_running)
				END
			)
		) AS amount_used
		FROM get_available_tbills
		WHERE (
			(available_amount > 0 AND avail_running <= $3) OR 
			(avail_running > $3 AND (avail_running - available_amount) < $3)
		) AND ( -- max value check 
			$3 <= (
				SELECT SUM(available_amount) FROM PUBLIC.tbills
			)
		)
	), get_tbill_fracs AS (
		INSERT INTO public.tbill_tokens(token_id, user_id, amount_invested, maturity_date, tenor_days, interest_id, bond_id, investment_date) 
			SELECT token_id, $1,
			token_data.amount_used, token_data.token_maturity_date, 
			$2 AS tenor_days, token_data.ir_id, token_data.bond_id, buying_date
			FROM (
				SELECT * FROM get_tbills_for_tokens AS bond_tokens
				CROSS JOIN 
				(
					SELECT * FROM get_interest_rate
				) AS t_ir
			) AS token_data
			CROSS JOIN gen_random_uuid() AS token_id
		RETURNING bond_id, amount_invested
	), transact_cte AS (
		UPDATE PUBLIC.tbills
		SET available_amount = GREATEST(0, available_amount - get_tbill_fracs.amount_invested)
		FROM get_tbill_fracs
		WHERE uuid = get_tbill_fracs.bond_id
		RETURNING *
	)
	
	UPDATE PUBLIC.user as u
	SET balance = GREATEST(0, balance - $3)
	FROM transact_cte
	WHERE u.uuid = $1 AND amount_invested > 0
	RETURNING *;
		`, user.UserId, user.TenorDays, user.AmountInvested)
	if err != nil || cmdTag.RowsAffected() == 0 {
		var errorStr string
		if err != nil {
			errorStr = err.Error()
		} else {
			errorStr = `Something went wrong in the fraction purchase query:
Possible causes are:
1. Maturity Date > Token Duration
2. Insufficient User balance
3. Check bond available amount`
		}
		fmt.Fprintln(os.Stderr, errorStr)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		go qservices.EmailErrorLog(qservices.SubjTbillPurchaseErr, errorStr)
		return
	}
	tx.Commit(context.TODO())

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, http.StatusOK, http.StatusText(http.StatusOK))
}

func getUserInvestments(w http.ResponseWriter, r *http.Request, connPool *pgxpool.Pool) {
	/*
		ACCEPTS: user.national_id
		RETURNS:
		{
			investment_value: XYZ,
			investments: [
				* token info of all investments
				{
					amount_invested, maturity_date, tenor_days, interest_rate
				},...
			]
		}
	*/
	userId, err := extractUserIdFromToken(w, r)
	if err != nil {
		return
	}

	rows, err := connPool.Query(context.Background(), `
	SELECT *, FLOOR(inv_info.deposit + 
		inv_info.deposit*(DATE_PART('day',(NOW() - inv_info.investment_date))/360)*inv_info.interest_rate/100) AS current_value
	FROM 
	(
		SELECT inv.token_id, inv.tenor_days, inv.maturity_date, inv.deposit, inv.investment_date, tbill_ir.interest_rate
		FROM (
			-- get total investment value
			SELECT token_id, tenor_days, maturity_date, SUM(amount_invested) AS deposit, interest_id, investment_date
			FROM
			PUBLIC.tbill_tokens
			WHERE user_id = $1 AND valid = true
		GROUP BY token_id, tenor_days, maturity_date, interest_id, investment_date
		) AS inv
		INNER JOIN PUBLIC.tbill_interest_rates AS tbill_ir 
		ON tbill_ir.uuid = inv.interest_id
	) AS inv_info;
	`, userId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		go qservices.EmailErrorLog(qservices.SubjGetUserInvestErr, err.Error())
		return
	}
	defer rows.Close()

	var tokens []qstructs.TbillToken
	// do something with the res Rows
	for rows.Next() {
		var token qstructs.TbillToken
		err := rows.Scan(&token.TokenId, &token.TenorDays, &token.MaturityDate, &token.AmountInvested,
			&token.InvestmentDate, &token.InterestRate, &token.CurrentValue)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			go qservices.EmailErrorLog(qservices.SubjGetUserInvestErr, err.Error())
			return
		}
		tokens = append(tokens, token)
	}
	encoder := json.NewEncoder(w)
	err = encoder.Encode(tokens)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		go qservices.EmailErrorLog(qservices.SubjGetUserInvestErr, err.Error())
		return
	}
}

func getDigitalWallet(w http.ResponseWriter, r *http.Request, connPool *pgxpool.Pool) {
	userId, err := extractUserIdFromToken(w, r)
	if err != nil {
		return
	}
	var digitalBalance uint64
	err = connPool.QueryRow(context.Background(),
		"SELECT balance FROM PUBLIC.user WHERE uuid = $1", userId).Scan(&digitalBalance)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		go qservices.EmailErrorLog(qservices.SubjGetWalletErr, err.Error())
		return
	}
	fmt.Fprintf(w, `{"Balance": %d}`, digitalBalance)
}

func postTbillSell(w http.ResponseWriter, r *http.Request, connPool *pgxpool.Pool) {
	userId, err := extractUserIdFromToken(w, r)
	if err != nil {
		return
	}
	tokenId := r.URL.Query().Get("tokenId")
	if !qservices.ValidateUuid(tokenId) {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	var wdrawn_amount int64
	tx, err := connPool.BeginTx(context.TODO(), pgx.TxOptions{AccessMode: pgx.ReadWrite})
	if err != nil {
		fmt.Println("Error beginning transaction", err)
		go qservices.EmailErrorLog(qservices.SubjTbillSellErr, err.Error())
	}
	defer tx.Rollback(context.TODO())
	_, err = tx.Exec(context.TODO(), `
		with agg_amount_for_bond AS (
			SELECT bond_id, SUM(amount_invested) AS bond_return
				FROM PUBLIC.tbill_tokens
				WHERE valid = true AND token_id = $1 AND user_id = $2
			GROUP BY bond_id
		)
		-- @section 1. REPLENISH BONDS
		UPDATE PUBLIC.tbills AS a
		SET available_amount = available_amount + token.bond_return 
		FROM agg_amount_for_bond
		AS token
		WHERE token.bond_id = a.uuid;
	`, tokenId, userId)
	if err != nil {
		fmt.Println("error replenishing bonds", err)
		go qservices.EmailErrorLog(qservices.SubjTbillSellErr, err.Error())
		return
	}

	err = tx.QueryRow(context.TODO(), `
	with invalidate_tokens AS ( -- @section 2. Update token status
		UPDATE PUBLIC.tbill_tokens
		SET valid = false
		WHERE valid = true AND token_id = $1 AND user_id = $2
		RETURNING *
	), get_interest AS (
		SELECT inv.token_id, inv.amount_invested, inv.investment_date, ir.interest_rate
		FROM invalidate_tokens AS inv
		LEFT JOIN tbill_interest_rates AS ir ON inv.interest_id = ir.uuid
	), calc_tenor_frac AS (
		SELECT SUM(gi.amount_invested) AS tot_inv, gi.interest_rate,
		-- @comment	tenor_frac = (tenor_days|days_since_bought)/360(days in year per banks) @end
		DATE_PART('day',(NOW() - gi.investment_date))/360.0 AS tenor_frac
		FROM get_interest AS gi
		GROUP BY gi.interest_rate, gi.investment_date
	), calc_inv_return AS (
		SELECT
			-- @comment
			-- NOTE: tax_rate_percent_removed[tax rate is 15 - meaning (1-.15) = .85]
			--		 qaim holding rate is 1%
			-- for withdraws:
			-- [qaim early withdraw charge is .25%]
			-- investment*(tenor_frac*interest_rate - tenor_frac*1 - tenor_frac*.25) 
			-- @end
			tf.tot_inv + FLOOR(
				0.85*tf.tot_inv*(tf.tenor_frac*tf.interest_rate/100)-tf.tot_inv*((tf.tenor_frac*1/100)+(.25/100))
			) AS inv_return
		FROM calc_tenor_frac AS tf
		GROUP BY tf.tot_inv, tf.interest_rate, tf.tenor_frac
	)
	
	UPDATE PUBLIC.user
	SET balance = balance + tot_inv.inv_return
	FROM calc_inv_return AS tot_inv
	WHERE uuid = $2
	RETURNING tot_inv.inv_return;
	`, tokenId, userId).Scan(&wdrawn_amount)
	if err != nil {
		fmt.Println("error updating token and user balance", err)
		go qservices.EmailErrorLog(qservices.SubjTbillSellErr, err.Error())
		return
	}
	tx.Commit(context.TODO())

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, http.StatusOK, http.StatusText(http.StatusOK))
}

func postBalanceWithdraw(w http.ResponseWriter, r *http.Request, connPool *pgxpool.Pool) {
	if !qservices.ValidateContentType(r, qservices.ContentJson) {
		http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
		return
	}
	userId, err := extractUserIdFromToken(w, r)
	if err != nil {
		return
	}
	var req qstructs.UserBalanceWithdrawArgs
	err = qservices.DecodeJson(r, &req)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Error parsing request body", http.StatusBadRequest)
		return
	}
	req.UserId = userId

	var balance int64
	err = connPool.QueryRow(context.Background(), `
		with subtract_user_balance AS (
			SELECT uuid AS user_id, $1::BIGINT AS amount FROM
			PUBLIC.user
			WHERE uuid = $2 AND balance >= $1 AND withdraw_request_id IS NULL
		), create_wdraw_req AS (
			INSERT INTO PUBLIC.user_withdraw_requests (user_id, amount)
			SELECT * FROM subtract_user_balance
			RETURNING request_id
		)
		
		UPDATE PUBLIC.user
		SET withdraw_request_id = wdraw.request_id, balance = balance - $1
		FROM create_wdraw_req AS wdraw
		WHERE uuid = $2
		RETURNING balance;
	`, req.Amount, req.UserId).Scan(&balance)
	if err != nil {
		if err.Error() == qservices.StatusEmptyRequest {
			fmt.Println(err)
			http.Error(w, "user has a pending withdrawal request", http.StatusConflict)
			return
		}
		fmt.Println("user wdraw req err", err)
		http.Error(w, "Error creating fund withdrawal request", http.StatusInternalServerError)
		go qservices.EmailErrorLog(qservices.SubjBalanceWithdrawErr, err.Error())
		return
	}
	err = qservices.ServeJson(w, r, balance)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "error parsing results", http.StatusInternalServerError)
	}
}

func getWdrawRequest(w http.ResponseWriter, r *http.Request, connPool *pgxpool.Pool) {
	userId, err := extractUserIdFromToken(w, r)
	if err != nil {
		return
	}
	var wdrawRequest qstructs.UserBalanceWdrawRequest
	err = connPool.QueryRow(context.Background(), `
		SELECT u.withdraw_Request_id, wdraw.amount, wdraw.request_date
		FROM PUBLIC.user AS u
		LEFT JOIN PUBLIC.user_withdraw_requests AS wdraw
		ON u.withdraw_Request_id = wdraw.request_id
		WHERE u.uuid = $1 AND wdraw.valid = TRUE;
	`, userId).Scan(&wdrawRequest.RequestId, &wdrawRequest.Amount, &wdrawRequest.RequestDate)
	if err != nil {
		if err.Error() == qservices.StatusEmptyRequest {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		fmt.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		go qservices.EmailErrorLog(qservices.SubjGetWithdrawReqErr, err.Error())
		return
	}
	err = qservices.ServeJson(w, r, wdrawRequest)
	if err != nil {
		fmt.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func UserHandler(w http.ResponseWriter, r *http.Request, connPool *pgxpool.Pool) {
	const prefix = "/user/"
	const prefixLen = len(prefix)
	switch path := r.URL.Path[prefixLen:]; path {
	case "login":
		qservices.MethodGuard(postUserLogin, w, r, connPool, "POST", qservices.NONE)
	case "signup":
		qservices.MethodGuard(postUserSignup, w, r, connPool, "POST", qservices.NONE)
	case "home/investments":
		qservices.MethodGuard(getUserInvestments, w, r, connPool, "GET", qservices.USER)
	case "home/wallet":
		qservices.MethodGuard(getDigitalWallet, w, r, connPool, "GET", qservices.USER)
	case "home/wallet/withdraw":
		qservices.MethodGuard(postBalanceWithdraw, w, r, connPool, "POST", qservices.USER)
	case "home/wallet/withdraw/all":
		qservices.MethodGuard(getWdrawRequest, w, r, connPool, "GET", qservices.USER)
	case "tbill/interest-rate":
		// TODO: add functionality to allow multiple user roles
		// like: qservices.USER | qservices.ADMIN
		qservices.MethodGuard(getInterestRate, w, r, connPool, "GET", qservices.USER)
	case "tbill/purchase":
		// TODO: add functionality to allow multiple user roles
		// like: qservices.USER | qservices.ADMIN
		qservices.MethodGuard(postTbillPurchase, w, r, connPool, "POST", qservices.USER)
	case "tbill/sell":
		qservices.MethodGuard(postTbillSell, w, r, connPool, "POST", qservices.USER)
	default:
		fmt.Fprintln(w, "404 page not found")
	}
}
