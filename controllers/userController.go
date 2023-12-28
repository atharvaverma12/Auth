package controllers

import (
	"strconv"

	helper "github.com/atharvaverma12/auth/helper"
	"golang.org/x/crypto/bcrypt"

	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/atharvaverma12/auth/database"
	"github.com/atharvaverma12/auth/models"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")
var validate = validator.New()

func HashPassword(password string) string{
	bytes , err := bcrypt.GenerateFromPassword([]byte(password),14)
	if err != nil {
		log.Panic(err)
	}
	return string(bytes)
}
func VerifyPassword(userPassword string, providedPassword string) (bool, string){
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte (userPassword))
	check := true
	msg := ""

	if err!= nil {
		msg = "email or password is incorrect"
		fmt.Println(msg)
		check= false
	}
	return check,msg
}

func Signup() gin.HandlerFunc {
	return func(c *gin.Context) {
		//make a context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User

		//bind the json that you have received from request body with struct
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}

		//validate struct with validate keyword used in struct
		validationErr := validate.Struct(user)
		if validationErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
			return
		}

		count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		defer cancel()
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occurred while checking for email"})
		}

		password := HashPassword(*user.Password)
		user.Password = &password
		count, err = userCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occurred while checking for phone"})
		}

		if count > 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "this email or phone number is already registered"})
		}
		user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.Updated_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.ID = primitive.NewObjectID()
		user.User_id = user.ID.Hex()
		token, refresh_token, _ := helper.GenerateAllTokens(*user.Email, *user.First_name, *user.Last_name, *user.User_type, *&user.User_id)
		user.Token = &token
		user.Refresh_token = &refresh_token
		resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)
		if insertErr != nil {
			msg := fmt.Sprintln("user item was not created")
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}
		c.JSON(http.StatusOK, resultInsertionNumber)
	}
}

func Login() gin.HandlerFunc{
return func(c *gin.Context) {
	var ctx, cancel = context.WithTimeout(context.Background(), 100 * time.Second)
	var user models.User
	var foundUser models.User
	if err := c.BindJSON(&user); err!= nil {
		c.JSON(http.StatusBadRequest, gin.H{"error":err.Error()})
		return
	}

	err := userCollection.FindOne(ctx,bson.M{"email": user.Email}).Decode(&foundUser)
	defer cancel()

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error":"email or password is incorrect"})
		return 
	}

	passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
	defer cancel()
	if passwordIsValid == false{
		c.JSON(http.StatusInternalServerError, gin.H{"error":msg})
		return
	}
	if foundUser.Email == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error":"user not found"})
	}
	token, refreshToken,_ := helper.GenerateAllTokens(*foundUser.Email,*foundUser.First_name, *foundUser.Last_name, *foundUser.User_type, foundUser.User_id)
    helper.UpdateAllTokens(token,refreshToken,foundUser.User_id)

	err = userCollection.FindOne(ctx,bson.M{"user_id":foundUser.User_id}).Decode(&foundUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error" : err.Error()})
		return 
	}
	c.JSON(http.StatusOK, foundUser)
}
}

func Getusers() gin.HandlerFunc{
	return func(c *gin.Context) {
		if err:= helper.CheckUserType(c,"ADMIN");err!= nil {
			c.JSON(http.StatusBadRequest, gin.H{"error":err.Error()})
			return 
		}
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

		recordPerPage, err := strcon
	}

}

func GetUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userId := c.Param("user_id")
		if err := helper.MatchUserTypeToUid(c, userId); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"Error": err.Error()})
			return
		}
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User
		err := userCollection.FindOne(ctx, bson.M{"user_id": userId}).Decode(&user) //gives back json and we need to decode it into something that golang understands
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, user)

	}
}
