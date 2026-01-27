package controller

import "errors"

// ErrAdminRequired 表示操作需要管理员权限
var ErrAdminRequired = errors.New("操作需要管理员权限")
