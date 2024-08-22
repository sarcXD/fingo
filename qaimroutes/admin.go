package qaimroutes

import (
	"context"
	"fmt"
	"net/http"
	"os"
	qservices "qaimbe/qaimservices"
	qstructs "qaimbe/qaimstructs"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// maximum list of records allowed to be fetched or verified at a single time (MANUALLY)
const q_MaxRecordsFetchSz int = 50

func postAdminSignup(w http.ResponseWriter, r *http.Request, connPool *pgxpool.Pool) {
	var admin qstructs.Admin
	/*
		* Writing file steps:
		- using a specific directory
		- check if dir exists
		- create dir
		-
	*/
	err := qservices.DecodeJson(r, &admin)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	if admin.Username == "" || admin.PhoneNum == "" || admin.Password == "" {
		fmt.Fprintln(w, "Error, missing required fields")
		return
	}

	fmt.Fprintf(w, "signup attempting for user %v\n", admin)
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(admin.Password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("error generating password")
		return
	}

	_, err = connPool.Exec(
		context.Background(),
		"INSERT INTO public.admin (uuid, user_name, phone_num, password_hash, verified) VALUES ((SELECT gen_random_uuid()), $1, $2, $3, $4)",
		admin.Username, admin.PhoneNum, hashedPass, false)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Error occurred in signup", http.StatusInternalServerError)

	}
	fmt.Fprintln(w, "User added successfully")
}

func postAdminVerify(w http.ResponseWriter, r *http.Request, connPool *pgxpool.Pool) {
	var admin qstructs.Admin
	/*
		* Writing file steps:
		- using a specific directory
		- check if dir exists
		- create dir
		-
	*/
	err := qservices.DecodeJson(r, &admin)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	if admin.Username == "" {
		fmt.Fprintln(w, "Error, missing required fields")
		return
	}

	fmt.Fprintf(w, "verifying admin %v\n", admin)
	_, err = connPool.Exec(
		context.Background(),
		`UPDATE PUBLIC.admin
		SET verified = true
		WHERE user_name = $1`,
		admin.Username)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Error occurred in verification", http.StatusInternalServerError)
	}
	fmt.Fprintln(w, "User verified successfully")
}

func postAdminLogin(w http.ResponseWriter, r *http.Request, connPool *pgxpool.Pool) {
	var admin qstructs.Admin
	err := qservices.DecodeJson(r, &admin)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	var auth qstructs.AdminAuth
	verified := true
	err = connPool.QueryRow(context.Background(), "select uuid, user_name, password_hash, verified from public.admin where user_name=$1", admin.Username).Scan(&auth.Uuid, &auth.Username, &auth.PasswordHash, &verified)
	if err != nil {
		if err.Error() != qservices.StatusEmptyRequest {
			fmt.Fprintf(os.Stderr, "Query failed: %v\n", err)
			// TODO(talha): implement a better way of exiting the program
			return
		}
	}

	if !verified {
		fmt.Fprintln(w, "Admin is not verified")
		return
	}
	err = bcrypt.CompareHashAndPassword(auth.PasswordHash, []byte(admin.Password))
	if err != nil {
		fmt.Fprintln(w, "incorrect username/password")
		return
	}
	token, err := qservices.CreateJwtToken(auth.Uuid, qservices.ADMIN)
	if err != nil {
		fmt.Println("error creating jwt token", err)
	}
	fmt.Fprintln(w, "You are logged in\nThis is your jwt auth token", token.Token)
}

/*
function fetches all unverified users
TODO: Paginated query for the future
*/
func getUsersUnverified(w http.ResponseWriter, r *http.Request, connPool *pgxpool.Pool) {
	rows, err := connPool.Query(
		context.Background(),
		"SELECT uuid, national_id, first_name, last_name, id_front, id_back, phone_number, iban, balance, verified FROM public.user WHERE verified = false")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Query failed: %v\n", err)
		return
	}
	defer rows.Close()

	/*
		We need to define an interface matching the query result testRes
		This is defined in the struct testRes
	*/
	var users []qstructs.UserGet
	for rows.Next() {
		var u qstructs.UserGet
		err := rows.Scan(&u.Uuid, &u.NationalId, &u.FirstName, &u.LastName, &u.IdFront, &u.IdBack, &u.PhoneNum, &u.Iban, &u.Balance, &u.Verified)
		if err != nil {
			fmt.Println(err)
			http.Error(w, "Error Fetching unverified users", http.StatusInternalServerError)
			return
		}
		users = append(users, u)
	}
	err = qservices.ServeJson(w, r, users)
	if err != nil {
		http.Error(w, "Error fetching unverified users", http.StatusInternalServerError)
		return
	}
}

/*
Function fetches all users in the system
*/
func getAllUsers(w http.ResponseWriter, r *http.Request, connPool *pgxpool.Pool) {
	rows, err := connPool.Query(context.Background(), "SELECT uuid, national_id, first_name, last_name, id_front, id_back, phone_number, iban, balance, verified FROM public.user")
	if err != nil {
		errorStr := fmt.Sprintf("Query failed: %v\n", err)
		http.Error(w, errorStr, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	/*
		We need to define an interface matching the query result testRes
		This is defined in the struct testRes
	*/
	var users []qstructs.UserGet
	for rows.Next() {
		var u qstructs.UserGet
		err := rows.Scan(&u.Uuid, &u.NationalId, &u.FirstName, &u.LastName, &u.IdFront, &u.IdBack, &u.PhoneNum, &u.Iban, &u.Balance, &u.Verified)
		if err != nil {
			fmt.Println(err)
			http.Error(w, "Error Fetching unverified users", http.StatusInternalServerError)
			return
		}
		users = append(users, u)
	}
	err = qservices.ServeJson(w, r, users)
	if err != nil {
		http.Error(w, "Error fetching users", http.StatusInternalServerError)
		return
	}
}

func getUserInfo(w http.ResponseWriter, r *http.Request, connPool *pgxpool.Pool) {
	nationalId := r.URL.Query().Get("national_id")
	var uInfo qstructs.UserGet
	err := connPool.QueryRow(context.Background(), `
		SELECT uuid, national_id, first_name, last_name, id_front, id_back, phone_number, iban, balance, verified 
		FROM public.user
		WHERE national_id = $1
	`, nationalId).Scan(&uInfo.Uuid, &uInfo.NationalId, &uInfo.FirstName, &uInfo.LastName, &uInfo.IdFront, &uInfo.IdBack,
		&uInfo.PhoneNum, &uInfo.Iban, &uInfo.Balance, &uInfo.Verified)
	if err != nil {
		fmt.Println("Error fetching user details", err)
		http.Error(w, "error fetching user info", http.StatusInternalServerError)
		return
	}
	err = qservices.ServeJson(w, r, uInfo)
	if err != nil {
		http.Error(w, "error writing user info", http.StatusInternalServerError)
		return
	}
}

func getUserImage(w http.ResponseWriter, r *http.Request, connPool *pgxpool.Pool) {
	/*
		Fetches the image stored in the s3 bucket with the supplied filename
	*/
	fname := r.URL.Query().Get("fname")
	fBuff, err := qservices.GetFromS3(fname)
	if err != nil {
		fmt.Fprintln(w, "error fetching file", err)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(fBuff)
}

func getUserWdrawRequests(w http.ResponseWriter, r *http.Request, connPool *pgxpool.Pool) {
	nationalId := r.URL.Query().Get("nationalId")
	if len(nationalId) == 0 {
		http.Error(w, "Invalid national id supplied", http.StatusBadRequest)
		return
	}
	rows, err := connPool.Query(context.Background(), `
	WITH user_id_from_national AS (
		SELECT uuid AS user_id, iban
		FROM PUBLIC.user
		WHERE national_id = $1 AND verified = TRUE
	)
			
	SELECT wdraw_req.request_id, wdraw_req.user_id, wdraw_req.amount, wdraw_req.request_date, u.iban
	FROM PUBLIC.user_withdraw_requests AS wdraw_req
	RIGHT JOIN user_id_from_national AS u
	ON wdraw_req.user_id = u.user_id
	WHERE VALID = TRUE;
	`, nationalId)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Error fetching withdrawal requests", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var requests []qstructs.UserBalanceWdrawRequest
	for rows.Next() {
		var request qstructs.UserBalanceWdrawRequest
		err = rows.Scan(&request.RequestId, &request.UserId, &request.Amount, &request.RequestDate, &request.Iban)
		if err != nil {
			fmt.Println(err)
			http.Error(w, "error fetching user withdrawal requests", http.StatusInternalServerError)
			return
		}
		requests = append(requests, request)
	}
	qservices.ServeJson(w, r, requests)
}

func getAllUserWdrawRequests(w http.ResponseWriter, r *http.Request, connPool *pgxpool.Pool) {
	rows, err := connPool.Query(context.Background(), `
		SELECT request_id, user_id, amount, request_date, u.iban
		FROM PUBLIC.user_withdraw_requests
		LEFT JOIN PUBLIC.user AS u
		ON user_id = u.uuid
		WHERE valid = TRUE;
	`)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "error fetching withdraw requests", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var requests []qstructs.UserBalanceWdrawRequest
	for rows.Next() {
		var request qstructs.UserBalanceWdrawRequest
		err = rows.Scan(&request.RequestId, &request.UserId, &request.Amount, &request.RequestDate, &request.Iban)
		if err != nil {
			fmt.Println(err)
			http.Error(w, "error fetching user withdrawal requests", http.StatusInternalServerError)
			return
		}
		requests = append(requests, request)
	}
	qservices.ServeJson(w, r, requests)
}

func patchUserWdrawRequest(w http.ResponseWriter, r *http.Request, connPool *pgxpool.Pool) {
	requestId := r.URL.Query().Get("requestId")
	if len(requestId) == 0 {
		http.Error(w, "Missing request id", http.StatusBadRequest)
	}

	_, err := connPool.Exec(context.Background(), `
		WITH invalidate_wdraw_req AS (
			UPDATE PUBLIC.user_withdraw_requests
			SET VALID = FALSE
			WHERE request_id = $1
			RETURNING user_id
		)		
		UPDATE PUBLIC.user
		SET withdraw_request_id = NULL
		FROM invalidate_wdraw_req AS req
		WHERE uuid = req.user_id;
	`, requestId)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Error resolving withdraw request", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

/*
Verify a single or a list of users
*/
func postUsersVerify(w http.ResponseWriter, r *http.Request, connPool *pgxpool.Pool) {
	idList := make([]string, 0, q_MaxRecordsFetchSz) // ! When using automatic kyc change to remove user verification limit
	err := qservices.DecodeJson(r, &idList)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	_, err = connPool.Exec(
		context.Background(),
		"UPDATE public.user SET verified = true where national_id = ANY($1)", idList)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error in user update %v\n", err)
		return
	}
	fmt.Fprintf(w, "User(s) verified successfully")
}

func postAddUserBalance(w http.ResponseWriter, r *http.Request, connPool *pgxpool.Pool) {
	var userStats qstructs.UserUpdate
	err := qservices.DecodeJson(r, &userStats)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Error parsing request body", http.StatusBadRequest)
		return
	}
	var updated_balance int64
	err = connPool.QueryRow(context.Background(), `
		UPDATE PUBLIC.user
		SET balance = balance + $1
		WHERE national_id = $2 AND verified = true
		RETURNING balance
	`, userStats.Balance, userStats.NationalId).Scan(&updated_balance)
	if err != nil {
		fmt.Println("error in postAddUserBalance\n", err)
		http.Error(w, "Error updating balance", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "{balance: %d}", updated_balance)
}

func postAddTBillInterestRate(w http.ResponseWriter, r *http.Request, connPool *pgxpool.Pool) {
	/*
		* Format:
		1. Date: ISO string
		2. Interest Rate: Real32
	*/
	// get date and interest rate
	var ir qstructs.TbillInterestRate
	err := qservices.DecodeJson(r, &ir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	t, err := time.Parse(time.RFC3339, ir.Date)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// get UTC Date as ISO string
	fmtDate := t.UTC().Format(time.RFC3339)
	_, err = connPool.Exec(
		context.Background(),
		"INSERT INTO public.tbill_interest_rates (uuid, date, interest_rate) VALUES ((SELECT gen_random_uuid()), $1, $2)",
		fmtDate, ir.InterestRate)
	if err != nil {
		// TODO(talha): handle signup errors
		fmt.Fprintf(os.Stderr, "Query failed: %v\n", err)
		return
	}
	fmt.Fprintln(w, "interest rate added successfully")
}

func postAddTBillBonds(w http.ResponseWriter, r *http.Request, connPool *pgxpool.Pool) {
	var bonds []qstructs.TbillBond
	err := qservices.DecodeJson(r, &bonds)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	copyCount, err := connPool.CopyFrom(
		context.Background(),
		pgx.Identifier{"tbills"},
		[]string{"tenor_days", "issue_date", "interest_rate", "amount", "available_amount", "maturity_date"},
		pgx.CopyFromSlice(len(bonds), func(i int) ([]any, error) {
			// validate inputs
			// TODO: HTTP Error handling
			// TODO: INPUT VALIDATION
			if bonds[i].MaturityDate.IsZero() {
				newMaturityDate := bonds[i].IssueDate.AddDate(0, 0, int(bonds[i].TenorDays))
				bonds[i].MaturityDate = newMaturityDate
			}
			return []any{bonds[i].TenorDays, bonds[i].IssueDate, bonds[i].InterestRate, bonds[i].Amount,
				bonds[i].Amount, bonds[i].MaturityDate}, nil
		}),
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	fmt.Fprintln(w, copyCount, "Rows copied over")
}

func getCurrentTbills(w http.ResponseWriter, r *http.Request, connPool *pgxpool.Pool) {
	rows, err := connPool.Query(
		context.Background(),
		`SELECT uuid, tenor_days, amount, available_amount, interest_rate, issue_date, maturity_date
		 FROM PUBLIC.tbills where valid = true`,
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var tbills []qstructs.DbTbillEntry
	for rows.Next() {
		var tbill qstructs.DbTbillEntry
		err = rows.Scan(&tbill.Uuid, &tbill.TenorDays, &tbill.Amount, &tbill.AvailableAmount, &tbill.InterestRate,
			&tbill.IssueDate, &tbill.MaturityDate)
		if err != nil {
			fmt.Println(err)
			http.Error(w, "error fetching user tbill tokens", http.StatusInternalServerError)
			return
		}
		tbills = append(tbills, tbill)
	}
	qservices.ServeJson(w, r, tbills)
}

func AdminHandler(w http.ResponseWriter, r *http.Request, connPool *pgxpool.Pool) {
	const prefix = "/admin/"
	const prefixLen = len(prefix)

	switch path := r.URL.Path[prefixLen:]; path {
	case "signup":
		qservices.MethodGuard(postAdminSignup, w, r, connPool, "POST", qservices.SUPERUSER)
	case "verify":
		qservices.MethodGuard(postAdminVerify, w, r, connPool, "POST", qservices.SUPERUSER)
	case "login":
		qservices.MethodGuard(postAdminLogin, w, r, connPool, "POST", qservices.NONE)
	case "users/info":
		qservices.MethodGuard(getUserInfo, w, r, connPool, "GET", qservices.ADMIN)
	case "users/unverified":
		qservices.MethodGuard(getUsersUnverified, w, r, connPool, "GET", qservices.ADMIN)
	case "users/verify":
		qservices.MethodGuard(postUsersVerify, w, r, connPool, "POST", qservices.ADMIN)
	case "users/all":
		qservices.MethodGuard(getAllUsers, w, r, connPool, "GET", qservices.ADMIN)
	case "users/img":
		qservices.MethodGuard(getUserImage, w, r, connPool, "GET", qservices.ADMIN)
	case "users/wallet/add":
		qservices.MethodGuard(postAddUserBalance, w, r, connPool, "POST", qservices.ADMIN)
	case "users/wallet/withdraw":
		qservices.MethodGuard(getUserWdrawRequests, w, r, connPool, "GET", qservices.ADMIN)
	case "users/wallet/withdraw/resolve":
		qservices.MethodGuard(patchUserWdrawRequest, w, r, connPool, "PATCH", qservices.ADMIN)
	case "users/wallet/withdraw/all":
		qservices.MethodGuard(getAllUserWdrawRequests, w, r, connPool, "GET", qservices.ADMIN)
	case "tbill/interest-rate/add":
		qservices.MethodGuard(postAddTBillInterestRate, w, r, connPool, "POST", qservices.ADMIN)
	case "tbill/add":
		qservices.MethodGuard(postAddTBillBonds, w, r, connPool, "POST", qservices.ADMIN)
	case "tbill/all":
		qservices.MethodGuard(getCurrentTbills, w, r, connPool, "GET", qservices.ADMIN)
	default:
		fmt.Fprintln(w, "404 page not found")
	}
}
