package qaimstructs

import (
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/robfig/cron"
)

//	Structs that are used in multiple places, all will be placed here
//
// for structs that are specific to a file, they will remain in those files.
type ConnProps struct {
	User   string
	Pass   string
	Addr   string
	DbName string
}

type Admin struct {
	Username string `json:"userName"`
	PhoneNum string `json:"phoneNumber"`
	Password string `json:"password"`
}

type AdminAuth struct {
	Uuid         string
	Username     string
	PasswordHash []byte
}

type User struct {
	NationalId string
	FirstName  string
	LastName   string
	PhoneNum   string
	Iban       string
	IdFront    string
	IdBack     string
	Password   string
}

type UserAuth struct {
	Uuid         string
	PasswordHash []byte
	NationalId   string
}

type UserGet struct {
	Uuid       string
	NationalId string
	FirstName  string
	LastName   string
	PhoneNum   string
	Iban       string
	Balance    int64
	IdFront    string
	IdBack     string
	Verified   bool
}

type UserUpdate struct {
	NationalId string
	Iban       string
	Balance    int64
	Verified   bool
}

type UserBalanceWithdrawArgs struct {
	UserId string
	Amount int64
}

type UserBalanceWdrawRequest struct {
	Amount      int64
	RequestId   string
	UserId      string
	RequestDate time.Time
	Iban        string
}

type TbillBond struct {
	Uuid         string
	TenorDays    uint32 // 30, 90, 120 days
	IssueDate    time.Time
	InterestRate float32
	Amount       int32
	MaturityDate time.Time
}

type DbTbillEntry struct {
	TenorDays       uint32 // 30, 90, 120 days
	IssueDate       time.Time
	InterestRate    float32
	AvailableAmount int32
	Uuid            string
	MaturityDate    time.Time
	Amount          int32
}

type TbillToken struct {
	TokenId        string
	UserId         string
	InterestRate   float32
	InterestId     string
	BondId         string
	AmountInvested int64
	CurrentValue   int64
	TenorDays      uint32 // 30, 90, 120 days
	MaturityDate   time.Time
	InvestmentDate time.Time
}

type TbillInterestRate struct {
	Uuid         string
	InterestRate float32
	Date         string
}

type CsvWdrawRequest struct {
	SerialNumber int8
	Date         time.Time
	UserId       string
	NationalId   string
	Iban         string
	Amount       int64
}

type CsvTbillHolding struct {
	SerialNumber   int8
	UserId         string
	Amount         int64
	InvestmentDate time.Time
	MaturityDate   time.Time
	Value          int64
}

type CsvTbillPurchase struct {
	SerialNumber   int8
	Date           string
	UserId         string
	NationalId     string
	InvestmentDate time.Time
	MaturityDate   time.Time
	Amount         int64
}

type ApplicationState struct {
	ConnPool   *pgxpool.Pool
	AwsSess    *session.Session
	CronRunner *cron.Cron
	MailList   *map[string][]string
	EnvType    string
}

type JsonEncodeSupported interface {
	string | int64 |
		[]UserGet | UserGet |
		UserBalanceWdrawRequest | []UserBalanceWdrawRequest |
		DbTbillEntry | []DbTbillEntry
}

type JsonDecodeSupported interface {
	string | []string |
		Admin | TbillInterestRate | []TbillBond |
		UserUpdate |
		UserBalanceWithdrawArgs
}
