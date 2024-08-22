package qaimservices

import (
	"bytes"
	"context"
	json "encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/mail"
	"net/smtp"
	"os"
	qs "qaimbe/qaimstructs"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/robfig/cron"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ! ********** CONSTANTS ***********
var GlobalState *qs.ApplicationState

// * Email Constants
const (
	LoggingTalha = "sarcxd@gmail.com"
	LoggingHasan = "hasan.tariq@qaim.finance"
)

const (
	ReportingRabi     = "R.nasir1995@gmail.com"
	ReportingRabiQaim = "Rabi.nasir@qaim.finance"
	ReportingTalha    = "talhaaamirwork@gmail.com"
)

const (
	MailReporting    = "reporting"
	MailLogging      = "logging"
	MailUserNotifier = "notifier"
)

const (
	SubjTbillHolding  = "Report: Customer Tbill Holding"
	SubjTbillPurchase = "Report: Customer Tbill Purchase"
	SubjFundsWithdraw = "Report: Customer Funds Withdraw Requests"
	SubjTbillMaturity = "Report: Customer Tbills Maturity"
)

const (
	SubjTbillPurchaseErr   = "Error: Customer Tbill Purchase Failed"
	SubjTbillSellErr       = "Error: Customer Tbill Sell Failed"
	SubjBalanceWithdrawErr = "Error: Customer Balance Withdraw Failed"
	SubjSignupErr          = "Error: Customer Signup Failed"
	SubjGetInterestRateErr = "Error: Get Interest Rate Failed"
	SubjGetUserInvestErr   = "Error: Get User Investments Failed"
	SubjGetWalletErr       = "Error: Get Digital Wallet Failed"
	SubjGetWithdrawReqErr  = "Error: Get Withdraw Request Failed"
)

const (
	SubjUserSignup = "Notification: User Sign up"
)

// * Error Strings
const (
	StatusEmptyRequest = "no rows in result set"
)

const (
	ContentJson          = "application/json"
	ContentMultipartForm = "multipart/form-data"
	ContentOctetStream   = "application/octet-stream"
	ContentPlainText     = "text/plain"
	ContentPng           = "image/png"
	ContentJpeg          = "image/jpeg"
)

const (
	EnvLocal = "local"
	EnvDev   = "dev"
	EnvProd  = "prod"
)

// ! ************ HELPER FUNCTIONS *******************
// declares a type RequestHandlers for functions with a http.ResponseWriter parameter
type requestHandlers func(w http.ResponseWriter, r *http.Request, conn *pgxpool.Pool)

func MethodGuard(fn requestHandlers, w http.ResponseWriter, r *http.Request, connPool *pgxpool.Pool, methodType string, userRole Role) {
	// check if method (GET/POST/PUT/DELETE) of request url matches the function on that path
	if r.Method == methodType {
		// user role (and hence jwt token ) not required
		// ! Only for Admin login, User login, User Signup endpoints
		if userRole == NONE {
			fn(w, r, connPool)
			return
		}
		if userRole == SUPERUSER {
			// get api key from request header
			apiKey := r.Header.Get("apiKey")
			if apiKey == os.Getenv("ADMIN_API_KEY") {
				fn(w, r, connPool)
				return
			}
		}
		// user role is required
		// verify jwt token, role and if token is expired
		b64Token := r.Header.Get("Token")
		if VerifyJwtToken(b64Token, userRole) {
			fn(w, r, connPool)
			return
		}
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
}

func ValidateContentType(r *http.Request, mimetype string) bool {
	ctStr := r.Header.Get("Content-type")
	if len(ctStr) > 0 {
		ctArr := strings.Split(ctStr, ";")
		contentType := ctArr[0]
		return contentType == mimetype
	}
	return false
}

// * Input Validation
func ValidateNationalId(str string) bool {
	/*
		len: 13
		chars: numbers
		regex: ^[0-9]{13}$
		[0-9]{13}: allow 13 characters between 0-9
		^, $: match only those defined by the filters
	*/
	rgx := regexp.MustCompile(`^[0-9]{13}$`)
	return rgx.MatchString(str)
}

func ValidatePhoneNum(str string) bool {
	/*
		len: 11
		chars: numbers
		regex: ^03[0-6][0-9]{8}$
		03: number must start with 03
		[0-6]: allow a single number between 0-6
		[0-9]{8}: allow 8 numbers in range 0-9
		^, $: match only those defined by the filters
	*/
	rgx := regexp.MustCompile(`^03[0-6][0-9]{8}$`)
	return rgx.MatchString(str)
}

func ValidateName(str string) bool {
	/*
		len: 50
		chars: alphabests
		regex: ^(?i)[A-Z]{1,50}$
		(?i): case insensitive matching
		[A-Z]: match alphabets
		{1,50}: allow in range 1 to 50 alphabets
		^, $: match only those defined by the filters
	*/
	rgx := regexp.MustCompile(`^(?i)[A-Z ]{1,50}$`)
	return rgx.MatchString(str)
}

func ValidateEmail(str string) bool {
	_, err := mail.ParseAddress(str)
	return err != nil
}

func ValidatePassword(str string) bool {
	/*
		len: 8-100
		chars-disallowed: .,*,\,\t,\n,\r,',",>,<
		regex: ^[^\.\*\\\t\n\r'"><]{8,}$
		^,$: Match exact string, from beginning to end
		[^ : disallow any inside square brackets
		\.\*\\\t\n\r'"><: characters to disallow
		{8,100}: allow passwords from 8-100
	*/
	rgx := regexp.MustCompile(`^[^\.\*\\\t\n\r'"><]{8,100}$`)
	return rgx.MatchString(str)
}

func ValidateIban(str string) bool {
	/*
		regex: ^PK[0-9]{2}[A-Z]{4}[0-9]{16}$
		^,$: matches entire string
		PK: must start with PK
		[0-9]{2}: must have two numbers following that
		[A-Z]{4}: must have 4 alphabets
		[0-9]{16}: must have 16 numerical digits
	*/
	rgx := regexp.MustCompile(`^PK[0-9]{2}[A-Z]{4}[0-9]{16}$`)
	return rgx.MatchString(str)
}

func ValidateUuid(str string) bool {
	/*
		regex: ^(?i)[A-Z0-9-]*$
		^,$: matches entire string
		(?i): allows case insensitive matching
		[A-Z0-9-]: allows alphabets, numbers and -
		*: apply to all characters in string
	*/
	rgx := regexp.MustCompile(`^(?i)[A-Z0-9-]*$`)
	return rgx.MatchString(str)
}

func ValidateImage(imgHeader *multipart.FileHeader) bool {
	/*
		maxlen: 2mb
		accept-type: [jpeg, png]
	*/
	imgBytes := imgHeader.Size
	imgMb := Mb64(imgBytes)
	if imgMb <= 2 {
		contentType := imgHeader.Header.Get("Content-Type")
		if contentType == ContentPng || contentType == ContentJpeg {
			return true
		}
	}
	return false
}

// ****************
func DecodeJson[V qs.JsonDecodeSupported](r *http.Request, v *V) error {
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(v)
	return err
}

func ServeJson[V qs.JsonEncodeSupported](w http.ResponseWriter, r *http.Request, v V) error {
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(v)
	return err
}

// ! ************ DataBase ******************
func ConnectToDb() (*pgxpool.Pool, error) {
	host := os.Getenv("DBHOST")
	port := os.Getenv("DBPORT")
	var cfg qs.ConnProps = qs.ConnProps{
		User:   os.Getenv("DBUSER"),
		Pass:   os.Getenv("DBPASS"),
		Addr:   host + ":" + port,
		DbName: os.Getenv("DBNAME"),
	}
	dbUrl := "postgres://" + cfg.User + ":" + cfg.Pass + "@" + cfg.Addr + "/" + cfg.DbName
	connPool, err := pgxpool.New(context.Background(), dbUrl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to connect to database: %v\n", err)
		return connPool, err
	}
	return connPool, nil
}

// ! *************** REPORTING ************

func SendEmailBytes(mailList []string, subject string, message bytes.Buffer) {
	if GlobalState.EnvType == EnvLocal {
		return
	}
	from := os.Getenv("EMAIL_USER")
	passwd := os.Getenv("EMAIL_PASS")
	to := mailList
	toHeader := strings.Join(to, ",")
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"
	body := []byte("To:" + toHeader + "\n" +
		"Subject: " + subject + " " + os.Getenv("DEPLOY_ENV") + "\n" +
		"\n" +
		message.String())
	auth := smtp.PlainAuth("", from, passwd, smtpHost)
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, body)
	if err != nil {
		log.Fatal(err)
	}
}

func SendEmailString(mailList []string, subject string, message string) {
	if GlobalState.EnvType == EnvLocal {
		return
	}
	from := os.Getenv("EMAIL_USER")
	passwd := os.Getenv("EMAIL_PASS")
	to := mailList
	toHeader := strings.Join(to, ",")
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"
	body := []byte("To:" + toHeader + "\n" +
		"Subject: " + subject + " " + os.Getenv("DEPLOY_ENV") + "\n" +
		"\n" +
		message)
	auth := smtp.PlainAuth("", from, passwd, smtpHost)
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, body)
	if err != nil {
		log.Fatal(err)
	}
}

func EmailErrorLog(subject string, err string) {
	if GlobalState.EnvType == EnvLocal {
		return
	}
	loggingList := (*GlobalState.MailList)[MailLogging]
	fmtErr := fmt.Sprintf("error code: %s", err)
	SendEmailString(loggingList, subject, fmtErr)
}

// ! *************** AWS ******************

func UploadToS3(file multipart.File, fname string) error {
	// don't want to be using aws services locally
	if GlobalState.EnvType == EnvLocal {
		return nil
	}
	// TODO(talha): Make function use channels to allow concurrent uploads
	svc := s3.New(GlobalState.AwsSess)
	s3Bucket := os.Getenv("AWS_S3_BUCKET")
	inp := s3.PutObjectInput{
		Bucket: aws.String(s3Bucket),
		Body:   file,
		Key:    aws.String(fname),
	}
	_, err := svc.PutObject(&inp)
	if err != nil {
		return err
	}
	return nil
}

func GetFromS3(fname string) ([]byte, error) {
	// TODO(talha): Make function use channels to allow concurrent downloads
	svc := s3.New(GlobalState.AwsSess)
	s3Bucket := os.Getenv("AWS_S3_BUCKET")
	input := &s3.GetObjectInput{
		Bucket: aws.String(s3Bucket),
		Key:    aws.String(fname),
	}

	result, err := svc.GetObject(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case s3.ErrCodeNoSuchKey:
				fmt.Println(s3.ErrCodeNoSuchKey, aerr.Error())
			case s3.ErrCodeInvalidObjectState:
				fmt.Println(s3.ErrCodeInvalidObjectState, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return nil, err
	}
	defer result.Body.Close()
	fBuff, err := io.ReadAll(result.Body)
	if err != nil {
		return nil, err
	}
	return fBuff, nil
}

func InitAppState(env string) error {
	awsRegion := os.Getenv("AWS_REGION")
	accessKeyID := os.Getenv("AWS_ACCESS_KEY")
	secretAccessKey := os.Getenv("AWS_SECRET_KEY")

	awsSess, err := session.NewSession(
		&aws.Config{
			Region: aws.String(awsRegion),
			Credentials: credentials.NewStaticCredentials(
				accessKeyID,
				secretAccessKey, "",
			),
		},
	)
	if err != nil {
		return err
	}

	connPool, err := ConnectToDb()
	if err != nil {
		dbErr := errors.New("error initializing db pool")
		return dbErr
	}

	mailList := make(map[string][]string, 3)
	mailList[MailReporting] = []string{ReportingTalha, LoggingHasan, ReportingRabi}
	mailList[MailLogging] = []string{LoggingTalha, LoggingHasan, ReportingRabi}
	mailList[MailUserNotifier] = []string{ReportingRabi, LoggingHasan, ReportingTalha}

	cronRunner := cron.New()
	// TODO: make these funcs use channels
	cronRunner.AddFunc("@every 12h", func() {
		ResolveTbills(mailList, connPool)
	})
	cronRunner.AddFunc("@every 12h", func() {
		CustomerTbillHolding(mailList, connPool)
	})
	cronRunner.AddFunc("@every 12h", func() {
		CustomerTbillPurchase(mailList, connPool)
	})
	cronRunner.AddFunc("@every 12h", func() {
		CustomerWithdrawRequest(mailList, connPool)
	})
	cronRunner.Start()

	GlobalState = &qs.ApplicationState{
		AwsSess: awsSess, ConnPool: connPool,
		CronRunner: cronRunner, MailList: &mailList,
		EnvType: env,
	}
	return nil
}
