// Copyright 2025 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import (
	"fmt"
	"slices"

	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/core"
	"github.com/xorm-io/xorm"
)

type Order struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(100) notnull pk" json:"name"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`
	UpdateTime  string `xorm:"varchar(100)" json:"updateTime"`
	DisplayName string `xorm:"varchar(100)" json:"displayName"`

	// Product Info
	Products     []string      `xorm:"varchar(1000)" json:"products"` // Support for multiple products per order. Using varchar(1000) for simple JSON array storage; can be refactored to separate table if needed
	ProductInfos []ProductInfo `xorm:"mediumtext" json:"productInfos"`

	// User Info
	User string `xorm:"varchar(100)" json:"user"`

	// Payment Info
	Payment  string  `xorm:"varchar(100)" json:"payment"`
	Price    float64 `json:"price"`
	Currency string  `xorm:"varchar(100)" json:"currency"`

	// Order State
	State   string `xorm:"varchar(100)" json:"state"`
	Message string `xorm:"varchar(2000)" json:"message"`

	// Coupon Info
	CouponName     string  `xorm:"varchar(100)" json:"couponName"`
	CouponDiscount float64 `json:"couponDiscount"` // Discount amount applied by coupon
}

type ProductInfo struct {
	Owner       string  `json:"owner"`
	Name        string  `json:"name"`
	CreatedTime string  `json:"createdTime,omitempty"`
	DisplayName string  `json:"displayName"`
	Image       string  `json:"image,omitempty"`
	Detail      string  `json:"detail,omitempty"`
	Price       float64 `json:"price"`
	Currency    string  `json:"currency,omitempty"`
	IsRecharge  bool    `json:"isRecharge,omitempty"`
	Quantity    int     `json:"quantity,omitempty"`
	PricingName string  `json:"pricingName,omitempty"`
	PlanName    string  `json:"planName,omitempty"`
}

func GetOrderCount(owner, field, value string) (int64, error) {
	session := GetSession(owner, -1, -1, field, value, "", "")
	return session.Count(&Order{Owner: owner})
}

func GetOrders(owner string) ([]*Order, error) {
	orders := []*Order{}
	err := ormer.Engine.Desc("created_time").Find(&orders, &Order{Owner: owner})
	if err != nil {
		return nil, err
	}

	return orders, nil
}

func GetUserOrders(owner, user string) ([]*Order, error) {
	orders := []*Order{}
	err := ormer.Engine.Desc("created_time").Find(&orders, &Order{Owner: owner, User: user})
	if err != nil {
		return nil, err
	}

	return orders, nil
}

func GetPaginationOrders(owner string, offset, limit int, field, value, sortField, sortOrder string) ([]*Order, error) {
	orders := []*Order{}
	session := GetSession(owner, offset, limit, field, value, sortField, sortOrder)
	err := session.Find(&orders, &Order{Owner: owner})
	if err != nil {
		return nil, err
	}

	return orders, nil
}

func getOrder(owner string, name string) (*Order, error) {
	if owner == "" || name == "" {
		return nil, nil
	}

	order := Order{Owner: owner, Name: name}
	existed, err := ormer.Engine.Get(&order)
	if err != nil {
		return nil, err
	}

	if existed {
		return &order, nil
	} else {
		return nil, nil
	}
}

func GetOrder(id string) (*Order, error) {
	owner, name, err := util.GetOwnerAndNameFromIdWithError(id)
	if err != nil {
		return nil, err
	}
	return getOrder(owner, name)
}

// LockOrderForPayment opens a DB transaction and locks the order row with
// session.ForUpdate(), the same pattern ApplyCoupon uses to serialize
// concurrent claims on a coupon row. It re-reads the order under that lock
// and re-checks that it is still "Created", closing the check-then-act
// window a plain GetOrder + in-memory check leaves open.
//
// On success, the caller owns the returned session and MUST eventually call
// either PersistOrderPaidInSession (to commit) or session.Rollback() (to
// release the lock without changing anything), followed by session.Close().
// On error, the session is already rolled back and closed for the caller.
func LockOrderForPayment(owner, name string) (*xorm.Session, *Order, error) {
	session := ormer.Engine.NewSession()
	if err := session.Begin(); err != nil {
		session.Close()
		return nil, nil, err
	}

	locked := Order{Owner: owner, Name: name}
	existed, err := session.ForUpdate().Get(&locked)
	if err != nil {
		_ = session.Rollback()
		session.Close()
		return nil, nil, err
	}
	if !existed {
		_ = session.Rollback()
		session.Close()
		return nil, nil, fmt.Errorf("the order: %s/%s does not exist", owner, name)
	}
	if locked.State != "Created" {
		_ = session.Rollback()
		session.Close()
		return nil, nil, fmt.Errorf("cannot pay for order: %s, current state is %s", locked.GetId(), locked.State)
	}

	return session, &locked, nil
}

// PersistOrderPaidInSession writes the final order fields (payment
// association and, for instant/synchronous providers, the Paid state)
// within the same locked transaction opened by LockOrderForPayment, using a
// conditional `WHERE state = 'Created'` as defense in depth on top of the
// row lock. It commits and closes the session on success; on failure or a
// lost race (affected == 0) it rolls back and closes the session, and the
// caller must not use it again either way.
func PersistOrderPaidInSession(session *xorm.Session, order *Order) (bool, error) {
	affected, err := session.ID(core.PK{order.Owner, order.Name}).
		Where("state = ?", "Created").
		AllCols().
		Update(order)
	if err != nil {
		_ = session.Rollback()
		session.Close()
		return false, err
	}
	if affected == 0 {
		_ = session.Rollback()
		session.Close()
		return false, fmt.Errorf("cannot pay for order: %s, current state is no longer Created", order.GetId())
	}

	if err := session.Commit(); err != nil {
		session.Close()
		return false, err
	}
	session.Close()
	return true, nil
}

func UpdateOrder(id string, order *Order) (bool, error) {
	owner, name, err := util.GetOwnerAndNameFromIdWithError(id)
	if err != nil {
		return false, err
	}

	var o *Order
	if o, err = getOrder(owner, name); err != nil {
		return false, err
	} else if o == nil {
		return false, nil
	}

	if o.State != order.State {
		if order.State == "Created" {
			order.UpdateTime = ""
		} else {
			order.UpdateTime = util.GetCurrentTime()
		}
	}

	if !slices.Equal(o.Products, order.Products) {
		existingInfos := make(map[string]ProductInfo, len(o.ProductInfos))
		for _, info := range o.ProductInfos {
			existingInfos[info.Name] = info
		}

		productInfos := make([]ProductInfo, 0, len(order.Products))
		products, err := getOrderProducts(owner, order.Products)
		if err != nil {
			return false, err
		}
		price := 0.0
		for _, product := range products {
			productInfo := ProductInfo{
				Name:        product.Name,
				DisplayName: product.DisplayName,
				Image:       product.Image,
				Detail:      product.Detail,
				Price:       product.Price,
				IsRecharge:  product.IsRecharge,
			}
			if existingInfo, ok := existingInfos[product.Name]; ok {
				// Keep historical product info; do not overwrite with current product.
				productInfo = existingInfo
			}
			price += productInfo.Price
			productInfos = append(productInfos, productInfo)
		}
		order.ProductInfos = productInfos
		order.Price = price
	}

	affected, err := ormer.Engine.ID(core.PK{owner, name}).AllCols().Update(order)
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func AddOrder(order *Order) (bool, error) {
	affected, err := ormer.Engine.Insert(order)
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func DeleteOrder(order *Order) (bool, error) {
	affected, err := ormer.Engine.ID(core.PK{order.Owner, order.Name}).Delete(&Order{})
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func (order *Order) GetId() string {
	return fmt.Sprintf("%s/%s", order.Owner, order.Name)
}
