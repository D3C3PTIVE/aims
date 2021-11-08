package credential

import (
	context "context"
	fmt "fmt"
	gorm1 "github.com/infobloxopen/atlas-app-toolkit/gorm"
	errors "github.com/infobloxopen/protoc-gen-gorm/errors"
	types "github.com/infobloxopen/protoc-gen-gorm/types"
	gorm "github.com/jinzhu/gorm"
	network "github.com/maxlandon/aims/proto/gen/go/network"
	go_uuid "github.com/satori/go.uuid"
	field_mask "google.golang.org/genproto/protobuf/field_mask"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	strings "strings"
	time "time"
)

type LoginORM struct {
	AccessLevel     string
	Core            *CoreORM `gorm:"not null;foreignkey:LoginId;association_foreignkey:Id"`
	CreatedAt       *time.Time
	HostId          go_uuid.UUID `gorm:"type:uuid;not null"`
	Id              go_uuid.UUID `gorm:"type:uuid;primary_key"`
	LastAttemptedAt *time.Time
	Service         *network.ServiceORM `gorm:"foreignkey:ServiceId;association_foreignkey:Id"`
	ServiceId       *go_uuid.UUID
	Status          int32
	UpdatedAt       *time.Time
}

// TableName overrides the default tablename generated by GORM
func (LoginORM) TableName() string {
	return "logins"
}

// ToORM runs the BeforeToORM hook if present, converts the fields of this
// object to ORM format, runs the AfterToORM hook, then returns the ORM object
func (m *Login) ToORM(ctx context.Context) (LoginORM, error) {
	to := LoginORM{}
	var err error
	if prehook, ok := interface{}(m).(LoginWithBeforeToORM); ok {
		if err = prehook.BeforeToORM(ctx, &to); err != nil {
			return to, err
		}
	}
	if m.Id != nil {
		to.Id, err = go_uuid.FromString(m.Id.Value)
		if err != nil {
			return to, err
		}
	} else {
		to.Id = go_uuid.Nil
	}
	if m.CreatedAt != nil {
		t := m.CreatedAt.AsTime()
		to.CreatedAt = &t
	}
	if m.UpdatedAt != nil {
		t := m.UpdatedAt.AsTime()
		to.UpdatedAt = &t
	}
	if m.LastAttemptedAt != nil {
		t := m.LastAttemptedAt.AsTime()
		to.LastAttemptedAt = &t
	}
	to.AccessLevel = m.AccessLevel
	to.Status = int32(m.Status)
	if m.Core != nil {
		tempCore, err := m.Core.ToORM(ctx)
		if err != nil {
			return to, err
		}
		to.Core = &tempCore
	}
	if m.Service != nil {
		tempService, err := m.Service.ToORM(ctx)
		if err != nil {
			return to, err
		}
		to.Service = &tempService
	}
	if m.HostId != nil {
		to.HostId, err = go_uuid.FromString(m.HostId.Value)
		if err != nil {
			return to, err
		}
	} else {
		to.HostId = go_uuid.Nil
	}
	if posthook, ok := interface{}(m).(LoginWithAfterToORM); ok {
		err = posthook.AfterToORM(ctx, &to)
	}
	return to, err
}

// ToPB runs the BeforeToPB hook if present, converts the fields of this
// object to PB format, runs the AfterToPB hook, then returns the PB object
func (m *LoginORM) ToPB(ctx context.Context) (Login, error) {
	to := Login{}
	var err error
	if prehook, ok := interface{}(m).(LoginWithBeforeToPB); ok {
		if err = prehook.BeforeToPB(ctx, &to); err != nil {
			return to, err
		}
	}
	to.Id = &types.UUID{Value: m.Id.String()}
	if m.CreatedAt != nil {
		to.CreatedAt = timestamppb.New(*m.CreatedAt)
	}
	if m.UpdatedAt != nil {
		to.UpdatedAt = timestamppb.New(*m.UpdatedAt)
	}
	if m.LastAttemptedAt != nil {
		to.LastAttemptedAt = timestamppb.New(*m.LastAttemptedAt)
	}
	to.AccessLevel = m.AccessLevel
	to.Status = LoginStatus(m.Status)
	if m.Core != nil {
		tempCore, err := m.Core.ToPB(ctx)
		if err != nil {
			return to, err
		}
		to.Core = &tempCore
	}
	if m.Service != nil {
		tempService, err := m.Service.ToPB(ctx)
		if err != nil {
			return to, err
		}
		to.Service = &tempService
	}
	to.HostId = &types.UUID{Value: m.HostId.String()}
	if posthook, ok := interface{}(m).(LoginWithAfterToPB); ok {
		err = posthook.AfterToPB(ctx, &to)
	}
	return to, err
}

// The following are interfaces you can implement for special behavior during ORM/PB conversions
// of type Login the arg will be the target, the caller the one being converted from

// LoginBeforeToORM called before default ToORM code
type LoginWithBeforeToORM interface {
	BeforeToORM(context.Context, *LoginORM) error
}

// LoginAfterToORM called after default ToORM code
type LoginWithAfterToORM interface {
	AfterToORM(context.Context, *LoginORM) error
}

// LoginBeforeToPB called before default ToPB code
type LoginWithBeforeToPB interface {
	BeforeToPB(context.Context, *Login) error
}

// LoginAfterToPB called after default ToPB code
type LoginWithAfterToPB interface {
	AfterToPB(context.Context, *Login) error
}

// DefaultCreateLogin executes a basic gorm create call
func DefaultCreateLogin(ctx context.Context, in *Login, db *gorm.DB) (*Login, error) {
	if in == nil {
		return nil, errors.NilArgumentError
	}
	ormObj, err := in.ToORM(ctx)
	if err != nil {
		return nil, err
	}
	if hook, ok := interface{}(&ormObj).(LoginORMWithBeforeCreate_); ok {
		if db, err = hook.BeforeCreate_(ctx, db); err != nil {
			return nil, err
		}
	}
	if err = db.Create(&ormObj).Error; err != nil {
		return nil, err
	}
	if hook, ok := interface{}(&ormObj).(LoginORMWithAfterCreate_); ok {
		if err = hook.AfterCreate_(ctx, db); err != nil {
			return nil, err
		}
	}
	pbResponse, err := ormObj.ToPB(ctx)
	return &pbResponse, err
}

type LoginORMWithBeforeCreate_ interface {
	BeforeCreate_(context.Context, *gorm.DB) (*gorm.DB, error)
}
type LoginORMWithAfterCreate_ interface {
	AfterCreate_(context.Context, *gorm.DB) error
}

func DefaultReadLogin(ctx context.Context, in *Login, db *gorm.DB) (*Login, error) {
	if in == nil {
		return nil, errors.NilArgumentError
	}
	ormObj, err := in.ToORM(ctx)
	if err != nil {
		return nil, err
	}
	if ormObj.Id == go_uuid.Nil {
		return nil, errors.EmptyIdError
	}
	if hook, ok := interface{}(&ormObj).(LoginORMWithBeforeReadApplyQuery); ok {
		if db, err = hook.BeforeReadApplyQuery(ctx, db); err != nil {
			return nil, err
		}
	}
	if db, err = gorm1.ApplyFieldSelection(ctx, db, nil, &LoginORM{}); err != nil {
		return nil, err
	}
	if hook, ok := interface{}(&ormObj).(LoginORMWithBeforeReadFind); ok {
		if db, err = hook.BeforeReadFind(ctx, db); err != nil {
			return nil, err
		}
	}
	ormResponse := LoginORM{}
	if err = db.Where(&ormObj).First(&ormResponse).Error; err != nil {
		return nil, err
	}
	if hook, ok := interface{}(&ormResponse).(LoginORMWithAfterReadFind); ok {
		if err = hook.AfterReadFind(ctx, db); err != nil {
			return nil, err
		}
	}
	pbResponse, err := ormResponse.ToPB(ctx)
	return &pbResponse, err
}

type LoginORMWithBeforeReadApplyQuery interface {
	BeforeReadApplyQuery(context.Context, *gorm.DB) (*gorm.DB, error)
}
type LoginORMWithBeforeReadFind interface {
	BeforeReadFind(context.Context, *gorm.DB) (*gorm.DB, error)
}
type LoginORMWithAfterReadFind interface {
	AfterReadFind(context.Context, *gorm.DB) error
}

func DefaultDeleteLogin(ctx context.Context, in *Login, db *gorm.DB) error {
	if in == nil {
		return errors.NilArgumentError
	}
	ormObj, err := in.ToORM(ctx)
	if err != nil {
		return err
	}
	if ormObj.Id == go_uuid.Nil {
		return errors.EmptyIdError
	}
	if hook, ok := interface{}(&ormObj).(LoginORMWithBeforeDelete_); ok {
		if db, err = hook.BeforeDelete_(ctx, db); err != nil {
			return err
		}
	}
	err = db.Where(&ormObj).Delete(&LoginORM{}).Error
	if err != nil {
		return err
	}
	if hook, ok := interface{}(&ormObj).(LoginORMWithAfterDelete_); ok {
		err = hook.AfterDelete_(ctx, db)
	}
	return err
}

type LoginORMWithBeforeDelete_ interface {
	BeforeDelete_(context.Context, *gorm.DB) (*gorm.DB, error)
}
type LoginORMWithAfterDelete_ interface {
	AfterDelete_(context.Context, *gorm.DB) error
}

func DefaultDeleteLoginSet(ctx context.Context, in []*Login, db *gorm.DB) error {
	if in == nil {
		return errors.NilArgumentError
	}
	var err error
	keys := []go_uuid.UUID{}
	for _, obj := range in {
		ormObj, err := obj.ToORM(ctx)
		if err != nil {
			return err
		}
		if ormObj.Id == go_uuid.Nil {
			return errors.EmptyIdError
		}
		keys = append(keys, ormObj.Id)
	}
	if hook, ok := (interface{}(&LoginORM{})).(LoginORMWithBeforeDeleteSet); ok {
		if db, err = hook.BeforeDeleteSet(ctx, in, db); err != nil {
			return err
		}
	}
	err = db.Where("id in (?)", keys).Delete(&LoginORM{}).Error
	if err != nil {
		return err
	}
	if hook, ok := (interface{}(&LoginORM{})).(LoginORMWithAfterDeleteSet); ok {
		err = hook.AfterDeleteSet(ctx, in, db)
	}
	return err
}

type LoginORMWithBeforeDeleteSet interface {
	BeforeDeleteSet(context.Context, []*Login, *gorm.DB) (*gorm.DB, error)
}
type LoginORMWithAfterDeleteSet interface {
	AfterDeleteSet(context.Context, []*Login, *gorm.DB) error
}

// DefaultStrictUpdateLogin clears / replaces / appends first level 1:many children and then executes a gorm update call
func DefaultStrictUpdateLogin(ctx context.Context, in *Login, db *gorm.DB) (*Login, error) {
	if in == nil {
		return nil, fmt.Errorf("Nil argument to DefaultStrictUpdateLogin")
	}
	ormObj, err := in.ToORM(ctx)
	if err != nil {
		return nil, err
	}
	lockedRow := &LoginORM{}
	db.Model(&ormObj).Set("gorm:query_option", "FOR UPDATE").Where("id=?", ormObj.Id).First(lockedRow)
	if hook, ok := interface{}(&ormObj).(LoginORMWithBeforeStrictUpdateCleanup); ok {
		if db, err = hook.BeforeStrictUpdateCleanup(ctx, db); err != nil {
			return nil, err
		}
	}
	filterCore := CoreORM{}
	if ormObj.Id == go_uuid.Nil {
		return nil, errors.EmptyIdError
	}
	filterCore.LoginId = new(go_uuid.UUID)
	*filterCore.LoginId = ormObj.Id
	if err = db.Where(filterCore).Delete(CoreORM{}).Error; err != nil {
		return nil, err
	}
	if hook, ok := interface{}(&ormObj).(LoginORMWithBeforeStrictUpdateSave); ok {
		if db, err = hook.BeforeStrictUpdateSave(ctx, db); err != nil {
			return nil, err
		}
	}
	if err = db.Save(&ormObj).Error; err != nil {
		return nil, err
	}
	if hook, ok := interface{}(&ormObj).(LoginORMWithAfterStrictUpdateSave); ok {
		if err = hook.AfterStrictUpdateSave(ctx, db); err != nil {
			return nil, err
		}
	}
	pbResponse, err := ormObj.ToPB(ctx)
	if err != nil {
		return nil, err
	}
	return &pbResponse, err
}

type LoginORMWithBeforeStrictUpdateCleanup interface {
	BeforeStrictUpdateCleanup(context.Context, *gorm.DB) (*gorm.DB, error)
}
type LoginORMWithBeforeStrictUpdateSave interface {
	BeforeStrictUpdateSave(context.Context, *gorm.DB) (*gorm.DB, error)
}
type LoginORMWithAfterStrictUpdateSave interface {
	AfterStrictUpdateSave(context.Context, *gorm.DB) error
}

// DefaultPatchLogin executes a basic gorm update call with patch behavior
func DefaultPatchLogin(ctx context.Context, in *Login, updateMask *field_mask.FieldMask, db *gorm.DB) (*Login, error) {
	if in == nil {
		return nil, errors.NilArgumentError
	}
	var pbObj Login
	var err error
	if hook, ok := interface{}(&pbObj).(LoginWithBeforePatchRead); ok {
		if db, err = hook.BeforePatchRead(ctx, in, updateMask, db); err != nil {
			return nil, err
		}
	}
	pbReadRes, err := DefaultReadLogin(ctx, &Login{Id: in.GetId()}, db)
	if err != nil {
		return nil, err
	}
	pbObj = *pbReadRes
	if hook, ok := interface{}(&pbObj).(LoginWithBeforePatchApplyFieldMask); ok {
		if db, err = hook.BeforePatchApplyFieldMask(ctx, in, updateMask, db); err != nil {
			return nil, err
		}
	}
	if _, err := DefaultApplyFieldMaskLogin(ctx, &pbObj, in, updateMask, "", db); err != nil {
		return nil, err
	}
	if hook, ok := interface{}(&pbObj).(LoginWithBeforePatchSave); ok {
		if db, err = hook.BeforePatchSave(ctx, in, updateMask, db); err != nil {
			return nil, err
		}
	}
	pbResponse, err := DefaultStrictUpdateLogin(ctx, &pbObj, db)
	if err != nil {
		return nil, err
	}
	if hook, ok := interface{}(pbResponse).(LoginWithAfterPatchSave); ok {
		if err = hook.AfterPatchSave(ctx, in, updateMask, db); err != nil {
			return nil, err
		}
	}
	return pbResponse, nil
}

type LoginWithBeforePatchRead interface {
	BeforePatchRead(context.Context, *Login, *field_mask.FieldMask, *gorm.DB) (*gorm.DB, error)
}
type LoginWithBeforePatchApplyFieldMask interface {
	BeforePatchApplyFieldMask(context.Context, *Login, *field_mask.FieldMask, *gorm.DB) (*gorm.DB, error)
}
type LoginWithBeforePatchSave interface {
	BeforePatchSave(context.Context, *Login, *field_mask.FieldMask, *gorm.DB) (*gorm.DB, error)
}
type LoginWithAfterPatchSave interface {
	AfterPatchSave(context.Context, *Login, *field_mask.FieldMask, *gorm.DB) error
}

// DefaultPatchSetLogin executes a bulk gorm update call with patch behavior
func DefaultPatchSetLogin(ctx context.Context, objects []*Login, updateMasks []*field_mask.FieldMask, db *gorm.DB) ([]*Login, error) {
	if len(objects) != len(updateMasks) {
		return nil, fmt.Errorf(errors.BadRepeatedFieldMaskTpl, len(updateMasks), len(objects))
	}

	results := make([]*Login, 0, len(objects))
	for i, patcher := range objects {
		pbResponse, err := DefaultPatchLogin(ctx, patcher, updateMasks[i], db)
		if err != nil {
			return nil, err
		}

		results = append(results, pbResponse)
	}

	return results, nil
}

// DefaultApplyFieldMaskLogin patches an pbObject with patcher according to a field mask.
func DefaultApplyFieldMaskLogin(ctx context.Context, patchee *Login, patcher *Login, updateMask *field_mask.FieldMask, prefix string, db *gorm.DB) (*Login, error) {
	if patcher == nil {
		return nil, nil
	} else if patchee == nil {
		return nil, errors.NilArgumentError
	}
	var err error
	var updatedCreatedAt bool
	var updatedUpdatedAt bool
	var updatedLastAttemptedAt bool
	var updatedCore bool
	var updatedService bool
	for i, f := range updateMask.Paths {
		if f == prefix+"Id" {
			patchee.Id = patcher.Id
			continue
		}
		if !updatedCreatedAt && strings.HasPrefix(f, prefix+"CreatedAt.") {
			if patcher.CreatedAt == nil {
				patchee.CreatedAt = nil
				continue
			}
			if patchee.CreatedAt == nil {
				patchee.CreatedAt = &timestamppb.Timestamp{}
			}
			childMask := &field_mask.FieldMask{}
			for j := i; j < len(updateMask.Paths); j++ {
				if trimPath := strings.TrimPrefix(updateMask.Paths[j], prefix+"CreatedAt."); trimPath != updateMask.Paths[j] {
					childMask.Paths = append(childMask.Paths, trimPath)
				}
			}
			if err := gorm1.MergeWithMask(patcher.CreatedAt, patchee.CreatedAt, childMask); err != nil {
				return nil, nil
			}
		}
		if f == prefix+"CreatedAt" {
			updatedCreatedAt = true
			patchee.CreatedAt = patcher.CreatedAt
			continue
		}
		if !updatedUpdatedAt && strings.HasPrefix(f, prefix+"UpdatedAt.") {
			if patcher.UpdatedAt == nil {
				patchee.UpdatedAt = nil
				continue
			}
			if patchee.UpdatedAt == nil {
				patchee.UpdatedAt = &timestamppb.Timestamp{}
			}
			childMask := &field_mask.FieldMask{}
			for j := i; j < len(updateMask.Paths); j++ {
				if trimPath := strings.TrimPrefix(updateMask.Paths[j], prefix+"UpdatedAt."); trimPath != updateMask.Paths[j] {
					childMask.Paths = append(childMask.Paths, trimPath)
				}
			}
			if err := gorm1.MergeWithMask(patcher.UpdatedAt, patchee.UpdatedAt, childMask); err != nil {
				return nil, nil
			}
		}
		if f == prefix+"UpdatedAt" {
			updatedUpdatedAt = true
			patchee.UpdatedAt = patcher.UpdatedAt
			continue
		}
		if !updatedLastAttemptedAt && strings.HasPrefix(f, prefix+"LastAttemptedAt.") {
			if patcher.LastAttemptedAt == nil {
				patchee.LastAttemptedAt = nil
				continue
			}
			if patchee.LastAttemptedAt == nil {
				patchee.LastAttemptedAt = &timestamppb.Timestamp{}
			}
			childMask := &field_mask.FieldMask{}
			for j := i; j < len(updateMask.Paths); j++ {
				if trimPath := strings.TrimPrefix(updateMask.Paths[j], prefix+"LastAttemptedAt."); trimPath != updateMask.Paths[j] {
					childMask.Paths = append(childMask.Paths, trimPath)
				}
			}
			if err := gorm1.MergeWithMask(patcher.LastAttemptedAt, patchee.LastAttemptedAt, childMask); err != nil {
				return nil, nil
			}
		}
		if f == prefix+"LastAttemptedAt" {
			updatedLastAttemptedAt = true
			patchee.LastAttemptedAt = patcher.LastAttemptedAt
			continue
		}
		if f == prefix+"AccessLevel" {
			patchee.AccessLevel = patcher.AccessLevel
			continue
		}
		if f == prefix+"Status" {
			patchee.Status = patcher.Status
			continue
		}
		if !updatedCore && strings.HasPrefix(f, prefix+"Core.") {
			updatedCore = true
			if patcher.Core == nil {
				patchee.Core = nil
				continue
			}
			if patchee.Core == nil {
				patchee.Core = &Core{}
			}
			if o, err := DefaultApplyFieldMaskCore(ctx, patchee.Core, patcher.Core, &field_mask.FieldMask{Paths: updateMask.Paths[i:]}, prefix+"Core.", db); err != nil {
				return nil, err
			} else {
				patchee.Core = o
			}
			continue
		}
		if f == prefix+"Core" {
			updatedCore = true
			patchee.Core = patcher.Core
			continue
		}
		if !updatedService && strings.HasPrefix(f, prefix+"Service.") {
			updatedService = true
			if patcher.Service == nil {
				patchee.Service = nil
				continue
			}
			if patchee.Service == nil {
				patchee.Service = &network.Service{}
			}
			if o, err := network.DefaultApplyFieldMaskService(ctx, patchee.Service, patcher.Service, &field_mask.FieldMask{Paths: updateMask.Paths[i:]}, prefix+"Service.", db); err != nil {
				return nil, err
			} else {
				patchee.Service = o
			}
			continue
		}
		if f == prefix+"Service" {
			updatedService = true
			patchee.Service = patcher.Service
			continue
		}
		if f == prefix+"HostId" {
			patchee.HostId = patcher.HostId
			continue
		}
	}
	if err != nil {
		return nil, err
	}
	return patchee, nil
}

// DefaultListLogin executes a gorm list call
func DefaultListLogin(ctx context.Context, db *gorm.DB) ([]*Login, error) {
	in := Login{}
	ormObj, err := in.ToORM(ctx)
	if err != nil {
		return nil, err
	}
	if hook, ok := interface{}(&ormObj).(LoginORMWithBeforeListApplyQuery); ok {
		if db, err = hook.BeforeListApplyQuery(ctx, db); err != nil {
			return nil, err
		}
	}
	db, err = gorm1.ApplyCollectionOperators(ctx, db, &LoginORM{}, &Login{}, nil, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	if hook, ok := interface{}(&ormObj).(LoginORMWithBeforeListFind); ok {
		if db, err = hook.BeforeListFind(ctx, db); err != nil {
			return nil, err
		}
	}
	db = db.Where(&ormObj)
	db = db.Order("id")
	ormResponse := []LoginORM{}
	if err := db.Find(&ormResponse).Error; err != nil {
		return nil, err
	}
	if hook, ok := interface{}(&ormObj).(LoginORMWithAfterListFind); ok {
		if err = hook.AfterListFind(ctx, db, &ormResponse); err != nil {
			return nil, err
		}
	}
	pbResponse := []*Login{}
	for _, responseEntry := range ormResponse {
		temp, err := responseEntry.ToPB(ctx)
		if err != nil {
			return nil, err
		}
		pbResponse = append(pbResponse, &temp)
	}
	return pbResponse, nil
}

type LoginORMWithBeforeListApplyQuery interface {
	BeforeListApplyQuery(context.Context, *gorm.DB) (*gorm.DB, error)
}
type LoginORMWithBeforeListFind interface {
	BeforeListFind(context.Context, *gorm.DB) (*gorm.DB, error)
}
type LoginORMWithAfterListFind interface {
	AfterListFind(context.Context, *gorm.DB, *[]LoginORM) error
}
