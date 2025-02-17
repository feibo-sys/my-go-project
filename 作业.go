package main

import (
	"crypto/rand"
	"fmt"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"time"
)

type User struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Avatar       string `json:"avatar"`
	Introduction string `json:"introduction"`
	Telephone    string `json:"telephone"`
	Qq           string `json:"qq"`
	Gender       string `json:"gender"`
	Email        string `json:"email"`
	Birthday     string `json:"birthday"`
	RefreshToken string `json:"refresh_token"`
	Token        string `json:"token"`
}
type Product struct {
	ProductID   string  `json:"product_id"`
	ProductName string  `json:"product_name"`
	Description string  `json:"description"`
	Type        string  `json:"type"`
	CommentNum  int     `json:"comment_num"`
	Price       float64 `json:"price"`
	IsAddedCar  bool    `json:"is_added_car"`
	Cover       string  `json:"cover"`
	PublishTime string  `json:"publish_time"`
	Link        string  `json:"link"`
}
type Order struct {
	OrderID    string    `json:"order_id"`
	UserID     string    `json:"user_id"`
	Products   []Product `json:"products"`
	TotalPrice float64   `json:"total"`
	OrderTime  string    `json:"order_time"`
	Status     string    `json:"status"`
}
type Comment struct {
	PostID      string `json:"post_id"`
	Content     string `json:"content"`
	UserID      string `json:"user_id"`
	Avatar      string `json:"avatar"`
	UserName    string `json:"username"`
	IsPraised   bool   `json:"is_praised"`
	PraiseCount int    `json:"praise_count"`
	ProductID   string `json:"product_id"`
}

var users []User
var products []Product
var orders []Order
var comments []Comment

func register(c *gin.Context) { //用户注册
	var newUser User
	if err := c.ShouldBindJSON(&newUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": 10001, "info": "参数错误", "data": nil})
		return
	}
	//检验用户名是否已经存在
	for _, user := range users {
		if user.Username == newUser.Username {
			c.JSON(http.StatusBadRequest, gin.H{"status": 10005, "info": "用户名已存在", "data": nil})
		}
	}
	//对密码进行哈希处理
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": 10002, "info": "密码加密失败", "data": nil})
		return
	}
	newUser.Password = string(hashedPassword)
	newUser.ID = fmt.Sprintf("%d", time.Now().UnixNano())
	users = append(users, newUser)
	c.JSON(http.StatusOK, gin.H{"status": 10000, "info": "success", "data": nil})
}
func generateToken() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}
func login(c *gin.Context) {
	var loginUser User
	if err := c.ShouldBindJSON(&loginUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": 10001, "info": "参数错误", "data": nil})
		return
	}
	for _, user := range users {
		if user.Username == loginUser.Username {
			err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginUser.Password))
			if err == nil {
				token, err := generateToken()
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"status": 10007, "info": "token生成失败", "data": nil})
					return
				}
				refreshToken, err := generateToken()
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"status": 10008, "info": "refreshToken生成失败", "data": nil})
					return
				}
				//更新用户的token和refreshToken
				user.Token = token
				user.RefreshToken = refreshToken
				c.JSON(http.StatusOK, gin.H{"status": 10000, "info": "success", "data": gin.H{
					"token": token, "refresh_Token": refreshToken}})
				return
			}
		}
	}
	c.JSON(http.StatusUnauthorized, gin.H{"status": 10003, "info": "用户名或密码错误", "data": nil})
}

// 刷新token
func refreshToken(c *gin.Context) {
	refreshToken := c.Query("refresh_token")
	if refreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"status": 10001, "info": "参数错误", "data": nil})
		return
	}
	for _, user := range users {
		if user.RefreshToken == refreshToken {
			newToken, err := generateToken()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"status": 10004, "info": "新token生成失败", "data": nil})
				return
			}
			newRefreshToken, err := generateToken()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"status": 10004, "info": "新refreshToken生成失败", "data": nil})
				return
			}
			//更新用户的token和refreshToken
			user.Token = newToken
			user.RefreshToken = newRefreshToken
			c.JSON(http.StatusOK, gin.H{"status": 10000, "info": "success", "data": gin.H{"token": newToken, "refresh_Token": newRefreshToken}})
			return
		}
	}
	c.JSON(http.StatusUnauthorized, gin.H{"status": 10006, "info": "无效的refreshToken", "data": nil})
}

// 修改用户密码
func changePassword(c *gin.Context) {
	token := c.GetHeader("Authorization")
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"status": 10009, "info": "未登录", "data": nil})
		return
	}
	var passwordChange struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&passwordChange); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": 10001, "info": "参数错误", "data": nil})
		return
	}
	for _, user := range users {
		if user.Token == token {
			err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(passwordChange.OldPassword))
			if err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"status": 10008, "info": "旧密码错误", "data": nil})
				return
			}
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(passwordChange.NewPassword), bcrypt.DefaultCost)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"status": 10004, "info": "密码加密失败", "data": nil})
				return
			}
			user.Password = string(hashedPassword)
			c.JSON(http.StatusOK, gin.H{"status": 10000, "info": "success", "data": user})
			return
		}
	}
	c.JSON(http.StatusUnauthorized, gin.H{"status": 10007, "info": "用户未找到", "data": nil})
}

// 获取用户信息
func getUserinfo(c *gin.Context) {
	token := c.GetHeader("Authorization")
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"status": 10009, "info": "未登录", "data": nil})
		return
	}
	for _, user := range users {
		if user.Token == token {
			c.JSON(http.StatusOK, gin.H{"status": 10000, "info": "success", "data": gin.H{"user": user}})
			return
		}
	}
	c.JSON(http.StatusUnauthorized, gin.H{"status": 10007, "info": "用户未找到", "data": nil})
}

// 修改用户信息
func updateInfo(c *gin.Context) {
	token := c.GetHeader("Authorization")
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"status": 10009, "info": "未登录", "data": nil})
		return
	}
	var updateInfo struct {
		Nickname string `json:"nickname"`
		Avatar   string `json:"avatar"`
	}
	if err := c.ShouldBindJSON(&updateInfo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": 10001, "info": "参数错误", "data": nil})
		return
	}
	for _, user := range users {
		if user.Token == token {
			if updateInfo.Nickname != "" {
				user.Username = updateInfo.Nickname
			}
			if updateInfo.Avatar != "" {
				user.Avatar = updateInfo.Avatar
			}
			c.JSON(http.StatusOK, gin.H{"status": 10000, "info": "success", "data": nil})
			return
		}
	}
	c.JSON(http.StatusUnauthorized, gin.H{"status": 10007, "info": "用户未找到", "data": nil})
}

// 获取商品列表
func getProductList(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": 10000, "info": "success", "data": gin.H{"ProductID": "1",
		"ProductName": "小蘑菇", "Description": "科幻末世小说", "Type": "书",
		"CommentNum": "100", "Price": "49.8", " IsAddedCar": "false",
		"Cover": "https://img3.doubanio.com/view/subject/l/public/s33687612.jpg", "PublishTime": "2020-7",
		"Link": "https://book.douban.com/subject/35139523/"}})
}

//获取评论
func getProductComment(c *gin.Context) {
	productID := c.Param("product_id")
	if productID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"status": 10001, "info": "参数错误", "data": nil})
		return
	}
}

//发表评论
func postComment(c *gin.Context) {
	var newComment Comment
	if err := c.ShouldBindJSON(&newComment); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": 10001, "info": "参数错误", "data": nil})
		return
	}
	comments = append(comments, newComment)
	c.JSON(http.StatusOK, gin.H{"status": 10000, "info": "success", "data": nil})
}

//删除评论
func deleteComment(c *gin.Context) {
	commentID := c.Param("comment_id")
	for i, comment := range comments {
		if comment.PostID == commentID {
			comments = append(comments[:i], comments[i+1:]...)
			c.JSON(http.StatusOK, gin.H{"status": 10000, "info": "success", "data": nil})
			return
		}
	}
	c.JSON(http.StatusUnauthorized, gin.H{"status": 10007, "info": "评论未找到", "data": nil})
}

//更新评论
func updateComment(c *gin.Context) {
	commentID := c.Param("comment_id")
	var updateComment struct {
		Content string `json:"content"`
	}
	if err := c.ShouldBindJSON(&updateComment); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": 10001, "info": "参数错误", "data": nil})
		return
	}
	for i, comment := range comments {
		if comment.PostID == commentID {
			comments[i].Content = updateComment.Content
			c.JSON(http.StatusOK, gin.H{"status": 10000, "info": "success", "data": nil})
			return
		}
	}
	c.JSON(http.StatusUnauthorized, gin.H{"status": 10007, "info": "评论未找到", "data": nil})
}

// 加入购物车
func addToCar(c *gin.Context) {
	token := c.GetHeader("Authorization")
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"status": 10008, "info": "未登录", "data": nil})
		return
	}
	productID := c.PostForm("product_id")
	if productID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"status": 10001, "info": "参数错误", "data": nil})
		return
	}
	for _, product := range products {
		if product.ProductID == productID {
			product.IsAddedCar = true
			c.JSON(http.StatusOK, gin.H{"status": 10000, "info": "success", "data": nil})
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"status": 10007, "info": "商品未找到", "data": nil})
}

// 下单
func placeOrder(c *gin.Context) {
	token := c.GetHeader("Authorization")
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"status": 10008, "info": "请先登录", "data": nil})
		return
	}
	var orderInfo struct {
		ProductIDs []string `json:"product_ids"`
	}
	if err := c.ShouldBindJSON(&orderInfo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": 10001, "info": "参数错误", "data": nil})
		return
	}
	var user *User
	for i := range users {
		if users[i].Token == token {
			user = &users[i]
			break
		}
	}
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": 10006, "info": "无效的token", "data": nil})
		return
	}
	var selectedProducts []Product
	totalPrice := 0.0
	for _, productID := range orderInfo.ProductIDs {
		for _, product := range products {
			if product.ProductID == productID {
				selectedProducts = append(selectedProducts, product)
				totalPrice += product.Price
				break
			}
		}
	}
	newOrder := Order{
		OrderID:    fmt.Sprintf("%d", time.Now().UnixNano()),
		UserID:     user.ID,
		Products:   selectedProducts,
		TotalPrice: totalPrice,
		OrderTime:  time.Now().Format("2006-01-02 15:04:05"),
		Status:     "未支付",
	}
	orders = append(orders, newOrder)
	c.JSON(http.StatusOK, gin.H{"status": 10000, "info": "success", "data": newOrder})
	return
}
func main() {
	r := gin.Default()
	r.POST("/user/register", register)
	r.POST("/user/token", login)
	r.GET("/user/token/refresh", refreshToken)
	r.PUT("/user/password", changePassword)
	r.GET("user/info", getUserinfo)
	r.GET("/comment", getProductComment)
	r.POST("/comment/post", postComment)
	r.DELETE("/comment/comment_id", deleteComment)
	r.PUT("/comment/update", updateComment)
	r.PUT("user/info", updateInfo)
	r.POST("/product/list", getProductList)
	r.POST("/product/addCar", addToCar)
	r.POST("/placeOrder", placeOrder)
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("启动服务失败：%v", err)
	}
}
