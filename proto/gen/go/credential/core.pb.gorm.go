package credential

import (
	context "context"
	fmt "fmt"
	gorm1 "github.com/infobloxopen/atlas-app-toolkit/gorm"
	errors "github.com/infobloxopen/protoc-gen-gorm/errors"
	types "github.com/infobloxopen/protoc-gen-gorm/types"
	gorm "github.com/jinzhu/gorm"
	go_uuid "github.com/satori/go.uuid"
	field_mask "google.golang.org/genproto/protobuf/field_mask"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	strings "strings"
	time "time"
)

type CoreORM struct {
	CreatedAt   *time.Time
	Id          go_uuid.UUID `gorm:"type:uuid;primary_key"`
	LoginsCount int32
	Origin      *OriginORM  `gorm:"not null;foreignkey:CoreId;association_foreignkey:Id"`
	Private     *PrivateORM `gorm:"foreignkey:CoreId;association_foreignkey:Id"`
	Public      *PublicORM  `gorm:"foreignkey:CoreId;association_foreignkey:Id"`
	Realm       *RealmORM   `gorm:"foreignkey:CoreId;association_foreignkey:Id"`
	UpdatedAt   *time.Time
}

// TableName overrides the default tablename generated by GORM
func (CoreORM) TableName() string {
	return "cores"
}

// ToORM runs the BeforeToORM hook if present, converts the fields of this
// object to ORM format, runs the AfterToORM hook, then returns the ORM object
func (m *Core) ToORM(ctx context.Context) (CoreORM, error) {
	to := CoreORM{}
	var err error
	if prehook, ok := interface{}(m).(CoreWithBeforeToORM); ok {
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
	if m.Origin != nil {
		tempOrigin, err := m.Origin.ToORM(ctx)
		if err != nil {
			return to, err
		}
		to.Origin = &tempOrigin
	}
	if m.Private != nil {
		tempPrivate, err := m.Private.ToORM(ctx)
		if err != nil {
			return to, err
		}
		to.Private = &tempPrivate
	}
	if m.Public != nil {
		tempPublic, err := m.Public.ToORM(ctx)
		if err != nil {
			return to, err
		}
		to.Public = &tempPublic
	}
	if m.Realm != nil {
		tempRealm, err := m.Realm.ToORM(ctx)
		if err != nil {
			return to, err
		}
		to.Realm = &tempRealm
	}
	to.LoginsCount = m.LoginsCount
	if posthook, ok := interface{}(m).(CoreWithAfterToORM); ok {
		err = posthook.AfterToORM(ctx, &to)
	}
	return to, err
}

// ToPB runs the BeforeToPB hook if present, converts the fields of this
// object to PB format, runs the AfterToPB hook, then returns the PB object
func (m *CoreORM) ToPB(ctx context.Context) (Core, error) {
	to := Core{}
	var err error
	if prehook, ok := interface{}(m).(CoreWithBeforeToPB); ok {
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
	if m.Origin != nil {
		tempOrigin, err := m.Origin.ToPB(ctx)
		if err != nil {
			return to, err
		}
		to.Origin = &tempOrigin
	}
	if m.Private != nil {
		tempPrivate, err := m.Private.ToPB(ctx)
		if err != nil {
			return to, err
		}
		to.Private = &tempPrivate
	}
	if m.Public != nil {
		tempPublic, err := m.Public.ToPB(ctx)
		if err != nil {
			return to, err
		}
		to.Public = &tempPublic
	}
	if m.Realm != nil {
		tempRealm, err := m.Realm.ToPB(ctx)
		if err != nil {
			return to, err
		}
		to.Realm = &tempRealm
	}
	to.LoginsCount = m.LoginsCount
	if posthook, ok := interface{}(m).(CoreWithAfterToPB); ok {
		err = posthook.AfterToPB(ctx, &to)
	}
	return to, err
}

// The following are interfaces you can implement for special behavior during ORM/PB conversions
// of type Core the arg will be the target, the caller the one being converted from

// CoreBeforeToORM called before default ToORM code
type CoreWithBeforeToORM interface {
	BeforeToORM(context.Context, *CoreORM) error
}

// CoreAfterToORM called after default ToORM code
type CoreWithAfterToORM interface {
	AfterToORM(context.Context, *CoreORM) error
}

// CoreBeforeToPB called before default ToPB code
type CoreWithBeforeToPB interface {
	BeforeToPB(context.Context, *Core) error
}

// CoreAfterToPB called after default ToPB code
type CoreWithAfterToPB interface {
	AfterToPB(context.Context, *Core) error
}

// DefaultCreateCore executes a basic gorm create call
func DefaultCreateCore(ctx context.Context, in *Core, db *gorm.DB) (*Core, error) {
	if in == nil {
		return nil, errors.NilArgumentError
	}
	ormObj, err := in.ToORM(ctx)
	if err != nil {
		return nil, err
	}
	if hook, ok := interface{}(&ormObj).(CoreORMWithBeforeCreate_); ok {
		if db, err = hook.BeforeCreate_(ctx, db); err != nil {
			return nil, err
		}
	}
	if err = db.Create(&ormObj).Error; err != nil {
		return nil, err
	}
	if hook, ok := interface{}(&ormObj).(CoreORMWithAfterCreate_); ok {
		if err = hook.AfterCreate_(ctx, db); err != nil {
			return nil, err
		}
	}
	pbResponse, err := ormObj.ToPB(ctx)
	return &pbResponse, err
}

type CoreORMWithBeforeCreate_ interface {
	BeforeCreate_(context.Context, *gorm.DB) (*gorm.DB, error)
}
type CoreORMWithAfterCreate_ interface {
	AfterCreate_(context.Context, *gorm.DB) error
}

func DefaultReadCore(ctx context.Context, in *Core, db *gorm.DB) (*Core, error) {
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
	if hook, ok := interface{}(&ormObj).(CoreORMWithBeforeReadApplyQuery); ok {
		if db, err = hook.BeforeReadApplyQuery(ctx, db); err != nil {
			return nil, err
		}
	}
	if db, err = gorm1.ApplyFieldSelection(ctx, db, nil, &CoreORM{}); err != nil {
		return nil, err
	}
	if hook, ok := interface{}(&ormObj).(CoreORMWithBeforeReadFind); ok {
		if db, err = hook.BeforeReadFind(ctx, db); err != nil {
			return nil, err
		}
	}
	ormResponse := CoreORM{}
	if err = db.Where(&ormObj).First(&ormResponse).Error; err != nil {
		return nil, err
	}
	if hook, ok := interface{}(&ormResponse).(CoreORMWithAfterReadFind); ok {
		if err = hook.AfterReadFind(ctx, db); err != nil {
			return nil, err
		}
	}
	pbResponse, err := ormResponse.ToPB(ctx)
	return &pbResponse, err
}

type CoreORMWithBeforeReadApplyQuery interface {
	BeforeReadApplyQuery(context.Context, *gorm.DB) (*gorm.DB, error)
}
type CoreORMWithBeforeReadFind interface {
	BeforeReadFind(context.Context, *gorm.DB) (*gorm.DB, error)
}
type CoreORMWithAfterReadFind interface {
	AfterReadFind(context.Context, *gorm.DB) error
}

func DefaultDeleteCore(ctx context.Context, in *Core, db *gorm.DB) error {
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
	if hook, ok := interface{}(&ormObj).(CoreORMWithBeforeDelete_); ok {
		if db, err = hook.BeforeDelete_(ctx, db); err != nil {
			return err
		}
	}
	err = db.Where(&ormObj).Delete(&CoreORM{}).Error
	if err != nil {
		return err
	}
	if hook, ok := interface{}(&ormObj).(CoreORMWithAfterDelete_); ok {
		err = hook.AfterDelete_(ctx, db)
	}
	return err
}

type CoreORMWithBeforeDelete_ interface {
	BeforeDelete_(context.Context, *gorm.DB) (*gorm.DB, error)
}
type CoreORMWithAfterDelete_ interface {
	AfterDelete_(context.Context, *gorm.DB) error
}

func DefaultDeleteCoreSet(ctx context.Context, in []*Core, db *gorm.DB) error {
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
	if hook, ok := (interface{}(&CoreORM{})).(CoreORMWithBeforeDeleteSet); ok {
		if db, err = hook.BeforeDeleteSet(ctx, in, db); err != nil {
			return err
		}
	}
	err = db.Where("id in (?)", keys).Delete(&CoreORM{}).Error
	if err != nil {
		return err
	}
	if hook, ok := (interface{}(&CoreORM{})).(CoreORMWithAfterDeleteSet); ok {
		err = hook.AfterDeleteSet(ctx, in, db)
	}
	return err
}

type CoreORMWithBeforeDeleteSet interface {
	BeforeDeleteSet(context.Context, []*Core, *gorm.DB) (*gorm.DB, error)
}
type CoreORMWithAfterDeleteSet interface {
	AfterDeleteSet(context.Context, []*Core, *gorm.DB) error
}

// DefaultStrictUpdateCore clears / replaces / appends first level 1:many children and then executes a gorm update call
func DefaultStrictUpdateCore(ctx context.Context, in *Core, db *gorm.DB) (*Core, error) {
	if in == nil {
		return nil, fmt.Errorf("Nil argument to DefaultStrictUpdateCore")
	}
	ormObj, err := in.ToORM(ctx)
	if err != nil {
		return nil, err
	}
	lockedRow := &CoreORM{}
	db.Model(&ormObj).Set("gorm:query_option", "FOR UPDATE").Where("id=?", ormObj.Id).First(lockedRow)
	if hook, ok := interface{}(&ormObj).(CoreORMWithBeforeStrictUpdateCleanup); ok {
		if db, err = hook.BeforeStrictUpdateCleanup(ctx, db); err != nil {
			return nil, err
		}
	}
	filterOrigin := OriginORM{}
	if ormObj.Id == go_uuid.Nil {
		return nil, errors.EmptyIdError
	}
	filterOrigin.CoreId = new(go_uuid.UUID)
	*filterOrigin.CoreId = ormObj.Id
	if err = db.Where(filterOrigin).Delete(OriginORM{}).Error; err != nil {
		return nil, err
	}
	filterPrivate := PrivateORM{}
	if ormObj.Id == go_uuid.Nil {
		return nil, errors.EmptyIdError
	}
	filterPrivate.CoreId = new(go_uuid.UUID)
	*filterPrivate.CoreId = ormObj.Id
	if err = db.Where(filterPrivate).Delete(PrivateORM{}).Error; err != nil {
		return nil, err
	}
	filterPublic := PublicORM{}
	if ormObj.Id == go_uuid.Nil {
		return nil, errors.EmptyIdError
	}
	filterPublic.CoreId = new(go_uuid.UUID)
	*filterPublic.CoreId = ormObj.Id
	if err = db.Where(filterPublic).Delete(PublicORM{}).Error; err != nil {
		return nil, err
	}
	filterRealm := RealmORM{}
	if ormObj.Id == go_uuid.Nil {
		return nil, errors.EmptyIdError
	}
	filterRealm.CoreId = new(go_uuid.UUID)
	*filterRealm.CoreId = ormObj.Id
	if err = db.Where(filterRealm).Delete(RealmORM{}).Error; err != nil {
		return nil, err
	}
	if hook, ok := interface{}(&ormObj).(CoreORMWithBeforeStrictUpdateSave); ok {
		if db, err = hook.BeforeStrictUpdateSave(ctx, db); err != nil {
			return nil, err
		}
	}
	if err = db.Save(&ormObj).Error; err != nil {
		return nil, err
	}
	if hook, ok := interface{}(&ormObj).(CoreORMWithAfterStrictUpdateSave); ok {
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

type CoreORMWithBeforeStrictUpdateCleanup interface {
	BeforeStrictUpdateCleanup(context.Context, *gorm.DB) (*gorm.DB, error)
}
type CoreORMWithBeforeStrictUpdateSave interface {
	BeforeStrictUpdateSave(context.Context, *gorm.DB) (*gorm.DB, error)
}
type CoreORMWithAfterStrictUpdateSave interface {
	AfterStrictUpdateSave(context.Context, *gorm.DB) error
}

// DefaultPatchCore executes a basic gorm update call with patch behavior
func DefaultPatchCore(ctx context.Context, in *Core, updateMask *field_mask.FieldMask, db *gorm.DB) (*Core, error) {
	if in == nil {
		return nil, errors.NilArgumentError
	}
	var pbObj Core
	var err error
	if hook, ok := interface{}(&pbObj).(CoreWithBeforePatchRead); ok {
		if db, err = hook.BeforePatchRead(ctx, in, updateMask, db); err != nil {
			return nil, err
		}
	}
	pbReadRes, err := DefaultReadCore(ctx, &Core{Id: in.GetId()}, db)
	if err != nil {
		return nil, err
	}
	pbObj = *pbReadRes
	if hook, ok := interface{}(&pbObj).(CoreWithBeforePatchApplyFieldMask); ok {
		if db, err = hook.BeforePatchApplyFieldMask(ctx, in, updateMask, db); err != nil {
			return nil, err
		}
	}
	if _, err := DefaultApplyFieldMaskCore(ctx, &pbObj, in, updateMask, "", db); err != nil {
		return nil, err
	}
	if hook, ok := interface{}(&pbObj).(CoreWithBeforePatchSave); ok {
		if db, err = hook.BeforePatchSave(ctx, in, updateMask, db); err != nil {
			return nil, err
		}
	}
	pbResponse, err := DefaultStrictUpdateCore(ctx, &pbObj, db)
	if err != nil {
		return nil, err
	}
	if hook, ok := interface{}(pbResponse).(CoreWithAfterPatchSave); ok {
		if err = hook.AfterPatchSave(ctx, in, updateMask, db); err != nil {
			return nil, err
		}
	}
	return pbResponse, nil
}

type CoreWithBeforePatchRead interface {
	BeforePatchRead(context.Context, *Core, *field_mask.FieldMask, *gorm.DB) (*gorm.DB, error)
}
type CoreWithBeforePatchApplyFieldMask interface {
	BeforePatchApplyFieldMask(context.Context, *Core, *field_mask.FieldMask, *gorm.DB) (*gorm.DB, error)
}
type CoreWithBeforePatchSave interface {
	BeforePatchSave(context.Context, *Core, *field_mask.FieldMask, *gorm.DB) (*gorm.DB, error)
}
type CoreWithAfterPatchSave interface {
	AfterPatchSave(context.Context, *Core, *field_mask.FieldMask, *gorm.DB) error
}

// DefaultPatchSetCore executes a bulk gorm update call with patch behavior
func DefaultPatchSetCore(ctx context.Context, objects []*Core, updateMasks []*field_mask.FieldMask, db *gorm.DB) ([]*Core, error) {
	if len(objects) != len(updateMasks) {
		return nil, fmt.Errorf(errors.BadRepeatedFieldMaskTpl, len(updateMasks), len(objects))
	}

	results := make([]*Core, 0, len(objects))
	for i, patcher := range objects {
		pbResponse, err := DefaultPatchCore(ctx, patcher, updateMasks[i], db)
		if err != nil {
			return nil, err
		}

		results = append(results, pbResponse)
	}

	return results, nil
}

// DefaultApplyFieldMaskCore patches an pbObject with patcher according to a field mask.
func DefaultApplyFieldMaskCore(ctx context.Context, patchee *Core, patcher *Core, updateMask *field_mask.FieldMask, prefix string, db *gorm.DB) (*Core, error) {
	if patcher == nil {
		return nil, nil
	} else if patchee == nil {
		return nil, errors.NilArgumentError
	}
	var err error
	var updatedCreatedAt bool
	var updatedUpdatedAt bool
	var updatedOrigin bool
	var updatedPrivate bool
	var updatedPublic bool
	var updatedRealm bool
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
		if !updatedOrigin && strings.HasPrefix(f, prefix+"Origin.") {
			updatedOrigin = true
			if patcher.Origin == nil {
				patchee.Origin = nil
				continue
			}
			if patchee.Origin == nil {
				patchee.Origin = &Origin{}
			}
			if o, err := DefaultApplyFieldMaskOrigin(ctx, patchee.Origin, patcher.Origin, &field_mask.FieldMask{Paths: updateMask.Paths[i:]}, prefix+"Origin.", db); err != nil {
				return nil, err
			} else {
				patchee.Origin = o
			}
			continue
		}
		if f == prefix+"Origin" {
			updatedOrigin = true
			patchee.Origin = patcher.Origin
			continue
		}
		if !updatedPrivate && strings.HasPrefix(f, prefix+"Private.") {
			updatedPrivate = true
			if patcher.Private == nil {
				patchee.Private = nil
				continue
			}
			if patchee.Private == nil {
				patchee.Private = &Private{}
			}
			if o, err := DefaultApplyFieldMaskPrivate(ctx, patchee.Private, patcher.Private, &field_mask.FieldMask{Paths: updateMask.Paths[i:]}, prefix+"Private.", db); err != nil {
				return nil, err
			} else {
				patchee.Private = o
			}
			continue
		}
		if f == prefix+"Private" {
			updatedPrivate = true
			patchee.Private = patcher.Private
			continue
		}
		if !updatedPublic && strings.HasPrefix(f, prefix+"Public.") {
			updatedPublic = true
			if patcher.Public == nil {
				patchee.Public = nil
				continue
			}
			if patchee.Public == nil {
				patchee.Public = &Public{}
			}
			if o, err := DefaultApplyFieldMaskPublic(ctx, patchee.Public, patcher.Public, &field_mask.FieldMask{Paths: updateMask.Paths[i:]}, prefix+"Public.", db); err != nil {
				return nil, err
			} else {
				patchee.Public = o
			}
			continue
		}
		if f == prefix+"Public" {
			updatedPublic = true
			patchee.Public = patcher.Public
			continue
		}
		if !updatedRealm && strings.HasPrefix(f, prefix+"Realm.") {
			updatedRealm = true
			if patcher.Realm == nil {
				patchee.Realm = nil
				continue
			}
			if patchee.Realm == nil {
				patchee.Realm = &Realm{}
			}
			if o, err := DefaultApplyFieldMaskRealm(ctx, patchee.Realm, patcher.Realm, &field_mask.FieldMask{Paths: updateMask.Paths[i:]}, prefix+"Realm.", db); err != nil {
				return nil, err
			} else {
				patchee.Realm = o
			}
			continue
		}
		if f == prefix+"Realm" {
			updatedRealm = true
			patchee.Realm = patcher.Realm
			continue
		}
		if f == prefix+"LoginsCount" {
			patchee.LoginsCount = patcher.LoginsCount
			continue
		}
	}
	if err != nil {
		return nil, err
	}
	return patchee, nil
}

// DefaultListCore executes a gorm list call
func DefaultListCore(ctx context.Context, db *gorm.DB) ([]*Core, error) {
	in := Core{}
	ormObj, err := in.ToORM(ctx)
	if err != nil {
		return nil, err
	}
	if hook, ok := interface{}(&ormObj).(CoreORMWithBeforeListApplyQuery); ok {
		if db, err = hook.BeforeListApplyQuery(ctx, db); err != nil {
			return nil, err
		}
	}
	db, err = gorm1.ApplyCollectionOperators(ctx, db, &CoreORM{}, &Core{}, nil, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	if hook, ok := interface{}(&ormObj).(CoreORMWithBeforeListFind); ok {
		if db, err = hook.BeforeListFind(ctx, db); err != nil {
			return nil, err
		}
	}
	db = db.Where(&ormObj)
	db = db.Order("id")
	ormResponse := []CoreORM{}
	if err := db.Find(&ormResponse).Error; err != nil {
		return nil, err
	}
	if hook, ok := interface{}(&ormObj).(CoreORMWithAfterListFind); ok {
		if err = hook.AfterListFind(ctx, db, &ormResponse); err != nil {
			return nil, err
		}
	}
	pbResponse := []*Core{}
	for _, responseEntry := range ormResponse {
		temp, err := responseEntry.ToPB(ctx)
		if err != nil {
			return nil, err
		}
		pbResponse = append(pbResponse, &temp)
	}
	return pbResponse, nil
}

type CoreORMWithBeforeListApplyQuery interface {
	BeforeListApplyQuery(context.Context, *gorm.DB) (*gorm.DB, error)
}
type CoreORMWithBeforeListFind interface {
	BeforeListFind(context.Context, *gorm.DB) (*gorm.DB, error)
}
type CoreORMWithAfterListFind interface {
	AfterListFind(context.Context, *gorm.DB, *[]CoreORM) error
}
