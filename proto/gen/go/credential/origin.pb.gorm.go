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

type OriginORM struct {
	CoreId    *go_uuid.UUID
	Cracker   string
	CreatedAt *time.Time
	Id        go_uuid.UUID        `gorm:"type:uuid;primary_key"`
	Service   *network.ServiceORM `gorm:"foreignkey:ServiceId;association_foreignkey:Id"`
	ServiceId *go_uuid.UUID
	SessionId go_uuid.UUID
	UpdatedAt *time.Time
}

// TableName overrides the default tablename generated by GORM
func (OriginORM) TableName() string {
	return "origins"
}

// ToORM runs the BeforeToORM hook if present, converts the fields of this
// object to ORM format, runs the AfterToORM hook, then returns the ORM object
func (m *Origin) ToORM(ctx context.Context) (OriginORM, error) {
	to := OriginORM{}
	var err error
	if prehook, ok := interface{}(m).(OriginWithBeforeToORM); ok {
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
	if m.SessionId != nil {
		to.SessionId, err = go_uuid.FromString(m.SessionId.Value)
		if err != nil {
			return to, err
		}
	} else {
		to.SessionId = go_uuid.Nil
	}
	to.Cracker = m.Cracker
	if m.Service != nil {
		tempService, err := m.Service.ToORM(ctx)
		if err != nil {
			return to, err
		}
		to.Service = &tempService
	}
	if posthook, ok := interface{}(m).(OriginWithAfterToORM); ok {
		err = posthook.AfterToORM(ctx, &to)
	}
	return to, err
}

// ToPB runs the BeforeToPB hook if present, converts the fields of this
// object to PB format, runs the AfterToPB hook, then returns the PB object
func (m *OriginORM) ToPB(ctx context.Context) (Origin, error) {
	to := Origin{}
	var err error
	if prehook, ok := interface{}(m).(OriginWithBeforeToPB); ok {
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
	to.SessionId = &types.UUID{Value: m.SessionId.String()}
	to.Cracker = m.Cracker
	if m.Service != nil {
		tempService, err := m.Service.ToPB(ctx)
		if err != nil {
			return to, err
		}
		to.Service = &tempService
	}
	if posthook, ok := interface{}(m).(OriginWithAfterToPB); ok {
		err = posthook.AfterToPB(ctx, &to)
	}
	return to, err
}

// The following are interfaces you can implement for special behavior during ORM/PB conversions
// of type Origin the arg will be the target, the caller the one being converted from

// OriginBeforeToORM called before default ToORM code
type OriginWithBeforeToORM interface {
	BeforeToORM(context.Context, *OriginORM) error
}

// OriginAfterToORM called after default ToORM code
type OriginWithAfterToORM interface {
	AfterToORM(context.Context, *OriginORM) error
}

// OriginBeforeToPB called before default ToPB code
type OriginWithBeforeToPB interface {
	BeforeToPB(context.Context, *Origin) error
}

// OriginAfterToPB called after default ToPB code
type OriginWithAfterToPB interface {
	AfterToPB(context.Context, *Origin) error
}

// DefaultCreateOrigin executes a basic gorm create call
func DefaultCreateOrigin(ctx context.Context, in *Origin, db *gorm.DB) (*Origin, error) {
	if in == nil {
		return nil, errors.NilArgumentError
	}
	ormObj, err := in.ToORM(ctx)
	if err != nil {
		return nil, err
	}
	if hook, ok := interface{}(&ormObj).(OriginORMWithBeforeCreate_); ok {
		if db, err = hook.BeforeCreate_(ctx, db); err != nil {
			return nil, err
		}
	}
	if err = db.Create(&ormObj).Error; err != nil {
		return nil, err
	}
	if hook, ok := interface{}(&ormObj).(OriginORMWithAfterCreate_); ok {
		if err = hook.AfterCreate_(ctx, db); err != nil {
			return nil, err
		}
	}
	pbResponse, err := ormObj.ToPB(ctx)
	return &pbResponse, err
}

type OriginORMWithBeforeCreate_ interface {
	BeforeCreate_(context.Context, *gorm.DB) (*gorm.DB, error)
}
type OriginORMWithAfterCreate_ interface {
	AfterCreate_(context.Context, *gorm.DB) error
}

func DefaultReadOrigin(ctx context.Context, in *Origin, db *gorm.DB) (*Origin, error) {
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
	if hook, ok := interface{}(&ormObj).(OriginORMWithBeforeReadApplyQuery); ok {
		if db, err = hook.BeforeReadApplyQuery(ctx, db); err != nil {
			return nil, err
		}
	}
	if db, err = gorm1.ApplyFieldSelection(ctx, db, nil, &OriginORM{}); err != nil {
		return nil, err
	}
	if hook, ok := interface{}(&ormObj).(OriginORMWithBeforeReadFind); ok {
		if db, err = hook.BeforeReadFind(ctx, db); err != nil {
			return nil, err
		}
	}
	ormResponse := OriginORM{}
	if err = db.Where(&ormObj).First(&ormResponse).Error; err != nil {
		return nil, err
	}
	if hook, ok := interface{}(&ormResponse).(OriginORMWithAfterReadFind); ok {
		if err = hook.AfterReadFind(ctx, db); err != nil {
			return nil, err
		}
	}
	pbResponse, err := ormResponse.ToPB(ctx)
	return &pbResponse, err
}

type OriginORMWithBeforeReadApplyQuery interface {
	BeforeReadApplyQuery(context.Context, *gorm.DB) (*gorm.DB, error)
}
type OriginORMWithBeforeReadFind interface {
	BeforeReadFind(context.Context, *gorm.DB) (*gorm.DB, error)
}
type OriginORMWithAfterReadFind interface {
	AfterReadFind(context.Context, *gorm.DB) error
}

func DefaultDeleteOrigin(ctx context.Context, in *Origin, db *gorm.DB) error {
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
	if hook, ok := interface{}(&ormObj).(OriginORMWithBeforeDelete_); ok {
		if db, err = hook.BeforeDelete_(ctx, db); err != nil {
			return err
		}
	}
	err = db.Where(&ormObj).Delete(&OriginORM{}).Error
	if err != nil {
		return err
	}
	if hook, ok := interface{}(&ormObj).(OriginORMWithAfterDelete_); ok {
		err = hook.AfterDelete_(ctx, db)
	}
	return err
}

type OriginORMWithBeforeDelete_ interface {
	BeforeDelete_(context.Context, *gorm.DB) (*gorm.DB, error)
}
type OriginORMWithAfterDelete_ interface {
	AfterDelete_(context.Context, *gorm.DB) error
}

func DefaultDeleteOriginSet(ctx context.Context, in []*Origin, db *gorm.DB) error {
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
	if hook, ok := (interface{}(&OriginORM{})).(OriginORMWithBeforeDeleteSet); ok {
		if db, err = hook.BeforeDeleteSet(ctx, in, db); err != nil {
			return err
		}
	}
	err = db.Where("id in (?)", keys).Delete(&OriginORM{}).Error
	if err != nil {
		return err
	}
	if hook, ok := (interface{}(&OriginORM{})).(OriginORMWithAfterDeleteSet); ok {
		err = hook.AfterDeleteSet(ctx, in, db)
	}
	return err
}

type OriginORMWithBeforeDeleteSet interface {
	BeforeDeleteSet(context.Context, []*Origin, *gorm.DB) (*gorm.DB, error)
}
type OriginORMWithAfterDeleteSet interface {
	AfterDeleteSet(context.Context, []*Origin, *gorm.DB) error
}

// DefaultStrictUpdateOrigin clears / replaces / appends first level 1:many children and then executes a gorm update call
func DefaultStrictUpdateOrigin(ctx context.Context, in *Origin, db *gorm.DB) (*Origin, error) {
	if in == nil {
		return nil, fmt.Errorf("Nil argument to DefaultStrictUpdateOrigin")
	}
	ormObj, err := in.ToORM(ctx)
	if err != nil {
		return nil, err
	}
	lockedRow := &OriginORM{}
	db.Model(&ormObj).Set("gorm:query_option", "FOR UPDATE").Where("id=?", ormObj.Id).First(lockedRow)
	if hook, ok := interface{}(&ormObj).(OriginORMWithBeforeStrictUpdateCleanup); ok {
		if db, err = hook.BeforeStrictUpdateCleanup(ctx, db); err != nil {
			return nil, err
		}
	}
	if hook, ok := interface{}(&ormObj).(OriginORMWithBeforeStrictUpdateSave); ok {
		if db, err = hook.BeforeStrictUpdateSave(ctx, db); err != nil {
			return nil, err
		}
	}
	if err = db.Save(&ormObj).Error; err != nil {
		return nil, err
	}
	if hook, ok := interface{}(&ormObj).(OriginORMWithAfterStrictUpdateSave); ok {
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

type OriginORMWithBeforeStrictUpdateCleanup interface {
	BeforeStrictUpdateCleanup(context.Context, *gorm.DB) (*gorm.DB, error)
}
type OriginORMWithBeforeStrictUpdateSave interface {
	BeforeStrictUpdateSave(context.Context, *gorm.DB) (*gorm.DB, error)
}
type OriginORMWithAfterStrictUpdateSave interface {
	AfterStrictUpdateSave(context.Context, *gorm.DB) error
}

// DefaultPatchOrigin executes a basic gorm update call with patch behavior
func DefaultPatchOrigin(ctx context.Context, in *Origin, updateMask *field_mask.FieldMask, db *gorm.DB) (*Origin, error) {
	if in == nil {
		return nil, errors.NilArgumentError
	}
	var pbObj Origin
	var err error
	if hook, ok := interface{}(&pbObj).(OriginWithBeforePatchRead); ok {
		if db, err = hook.BeforePatchRead(ctx, in, updateMask, db); err != nil {
			return nil, err
		}
	}
	pbReadRes, err := DefaultReadOrigin(ctx, &Origin{Id: in.GetId()}, db)
	if err != nil {
		return nil, err
	}
	pbObj = *pbReadRes
	if hook, ok := interface{}(&pbObj).(OriginWithBeforePatchApplyFieldMask); ok {
		if db, err = hook.BeforePatchApplyFieldMask(ctx, in, updateMask, db); err != nil {
			return nil, err
		}
	}
	if _, err := DefaultApplyFieldMaskOrigin(ctx, &pbObj, in, updateMask, "", db); err != nil {
		return nil, err
	}
	if hook, ok := interface{}(&pbObj).(OriginWithBeforePatchSave); ok {
		if db, err = hook.BeforePatchSave(ctx, in, updateMask, db); err != nil {
			return nil, err
		}
	}
	pbResponse, err := DefaultStrictUpdateOrigin(ctx, &pbObj, db)
	if err != nil {
		return nil, err
	}
	if hook, ok := interface{}(pbResponse).(OriginWithAfterPatchSave); ok {
		if err = hook.AfterPatchSave(ctx, in, updateMask, db); err != nil {
			return nil, err
		}
	}
	return pbResponse, nil
}

type OriginWithBeforePatchRead interface {
	BeforePatchRead(context.Context, *Origin, *field_mask.FieldMask, *gorm.DB) (*gorm.DB, error)
}
type OriginWithBeforePatchApplyFieldMask interface {
	BeforePatchApplyFieldMask(context.Context, *Origin, *field_mask.FieldMask, *gorm.DB) (*gorm.DB, error)
}
type OriginWithBeforePatchSave interface {
	BeforePatchSave(context.Context, *Origin, *field_mask.FieldMask, *gorm.DB) (*gorm.DB, error)
}
type OriginWithAfterPatchSave interface {
	AfterPatchSave(context.Context, *Origin, *field_mask.FieldMask, *gorm.DB) error
}

// DefaultPatchSetOrigin executes a bulk gorm update call with patch behavior
func DefaultPatchSetOrigin(ctx context.Context, objects []*Origin, updateMasks []*field_mask.FieldMask, db *gorm.DB) ([]*Origin, error) {
	if len(objects) != len(updateMasks) {
		return nil, fmt.Errorf(errors.BadRepeatedFieldMaskTpl, len(updateMasks), len(objects))
	}

	results := make([]*Origin, 0, len(objects))
	for i, patcher := range objects {
		pbResponse, err := DefaultPatchOrigin(ctx, patcher, updateMasks[i], db)
		if err != nil {
			return nil, err
		}

		results = append(results, pbResponse)
	}

	return results, nil
}

// DefaultApplyFieldMaskOrigin patches an pbObject with patcher according to a field mask.
func DefaultApplyFieldMaskOrigin(ctx context.Context, patchee *Origin, patcher *Origin, updateMask *field_mask.FieldMask, prefix string, db *gorm.DB) (*Origin, error) {
	if patcher == nil {
		return nil, nil
	} else if patchee == nil {
		return nil, errors.NilArgumentError
	}
	var err error
	var updatedCreatedAt bool
	var updatedUpdatedAt bool
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
		if f == prefix+"SessionId" {
			patchee.SessionId = patcher.SessionId
			continue
		}
		if f == prefix+"Cracker" {
			patchee.Cracker = patcher.Cracker
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
	}
	if err != nil {
		return nil, err
	}
	return patchee, nil
}

// DefaultListOrigin executes a gorm list call
func DefaultListOrigin(ctx context.Context, db *gorm.DB) ([]*Origin, error) {
	in := Origin{}
	ormObj, err := in.ToORM(ctx)
	if err != nil {
		return nil, err
	}
	if hook, ok := interface{}(&ormObj).(OriginORMWithBeforeListApplyQuery); ok {
		if db, err = hook.BeforeListApplyQuery(ctx, db); err != nil {
			return nil, err
		}
	}
	db, err = gorm1.ApplyCollectionOperators(ctx, db, &OriginORM{}, &Origin{}, nil, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	if hook, ok := interface{}(&ormObj).(OriginORMWithBeforeListFind); ok {
		if db, err = hook.BeforeListFind(ctx, db); err != nil {
			return nil, err
		}
	}
	db = db.Where(&ormObj)
	db = db.Order("id")
	ormResponse := []OriginORM{}
	if err := db.Find(&ormResponse).Error; err != nil {
		return nil, err
	}
	if hook, ok := interface{}(&ormObj).(OriginORMWithAfterListFind); ok {
		if err = hook.AfterListFind(ctx, db, &ormResponse); err != nil {
			return nil, err
		}
	}
	pbResponse := []*Origin{}
	for _, responseEntry := range ormResponse {
		temp, err := responseEntry.ToPB(ctx)
		if err != nil {
			return nil, err
		}
		pbResponse = append(pbResponse, &temp)
	}
	return pbResponse, nil
}

type OriginORMWithBeforeListApplyQuery interface {
	BeforeListApplyQuery(context.Context, *gorm.DB) (*gorm.DB, error)
}
type OriginORMWithBeforeListFind interface {
	BeforeListFind(context.Context, *gorm.DB) (*gorm.DB, error)
}
type OriginORMWithAfterListFind interface {
	AfterListFind(context.Context, *gorm.DB, *[]OriginORM) error
}
